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
            mock.patch.object(
                competition,
                "_workspace_route_shadow_calibration",
                return_value={
                    "schema_version": 1,
                    "mode": "shadow_only",
                    "eligible": False,
                    "applied_to_live_route": False,
                    "execution_authorized": False,
                },
            ),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()


    def _route_selection(self, *, max_candidates: int, allow_paid: bool) -> dict:
        routes = [
            {
                "route": "codex-sol-high",
                "harness": "codex",
                "model": "gpt-5.6-sol",
                "paid_only": False,
                "execution_eligible_if_separately_authorized": True,
            }
        ]
        if allow_paid and max_candidates >= 2:
            routes.append(
                {
                    "route": "claude-fable-5-contrast-high",
                    "harness": "claude",
                    "model": "claude-fable-5",
                    "paid_only": True,
                    "execution_eligible_if_separately_authorized": True,
                }
            )
        return {
            "status": "recommended",
            "state_error_type": None,
            "catalog_sha256": "a" * 64,
            "routes": routes[:max_candidates],
            "excluded": {},
        }

    def _route_contract(self, route_id: str, *, paid: bool = False) -> dict:
        if route_id == "codex-sol-high":
            contract = {
                "schema_version": 1,
                "catalog_sha256": "a" * 64,
                "route_id": route_id,
                "harness": "codex",
                "harness_binary": "codex",
                "model": "gpt-5.6-sol",
                "effort": "high",
                "argv_prefix": ["codexr", "architecture"],
                "permission_mode": None,
                "quota_pools": ["openai-agentic"],
                "paid_only": False,
                "authority": "advisory_only",
                "automatic_patch_apply": False,
            }
        elif route_id == "agy-gemini-flash-medium":
            contract = {
                "schema_version": 1,
                "catalog_sha256": "a" * 64,
                "route_id": route_id,
                "harness": "agy",
                "harness_binary": "agy",
                "model": "gemini-3.5-flash",
                "effort": "medium",
                "argv_prefix": ["agy", "--model", "Gemini 3.5 Flash (Medium)"],
                "permission_mode": None,
                "quota_pools": ["agy-gemini", "agy-account"],
                "paid_only": False,
                "authority": "advisory_only",
                "automatic_patch_apply": False,
            }
        else:
            if not paid:
                raise competition.coding_router.CodingAgentRouterError(
                    "paid-only route requires explicit paid execution authorization"
                )
            contract = {
                "schema_version": 1,
                "catalog_sha256": "a" * 64,
                "route_id": route_id,
                "harness": "claude",
                "harness_binary": "claude",
                "model": "claude-fable-5",
                "effort": "high",
                "argv_prefix": [
                    "claude",
                    "-p",
                    "--permission-mode",
                    "acceptEdits",
                    "--model",
                    "claude-fable-5",
                    "--effort",
                    "high",
                ],
                "permission_mode": "acceptEdits",
                "quota_pools": ["claude-pro"],
                "paid_only": True,
                "authority": "advisory_only",
                "automatic_patch_apply": False,
            }
        return {
            **contract,
            "route_contract_sha256": competition._sha256_json(contract),
        }

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

    def _authorized_start(self, **kwargs):
        kwargs.setdefault("max_budget_usd", 2.0)
        kwargs.setdefault("require_hard_budget", kwargs.get("provider") == "claude")
        with mock.patch.dict(
            os.environ,
            {competition.EXTERNAL_PROVIDER_BUDGET_CAP_ENV: "10"},
            clear=False,
        ):
            return competition.grabowski_agent_competition_start(**kwargs)

    def _start(self, *, provider: str = "claude", mode: str = "competitor", task: str = "Improve sample") -> dict:
        task_id = f"task-{provider}-{mode}"
        with mock.patch.object(competition.tasks, "grabowski_task_start", return_value=self._task_start(task_id)) as start:
            result = self._authorized_start(
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
        self.assertEqual(call["cwd"], str(self.state / result["competition_id"]))
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
        packet = competition._validated_packet(identifier)
        provider_workspace = self.state / identifier / "provider-workspace"
        prompt = b"test provider prompt\n"
        prompt_path = provider_workspace / "prompt.txt"
        if not prompt_path.exists():
            competition._atomic_bytes(prompt_path, prompt)
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
        if manifest["schema_version"] == 3 and manifest["provider"] == "codex":
            command = [
                "codexr",
                manifest["route_contract"]["argv_prefix"][1],
                "exec",
                "--sandbox",
                "read-only",
            ]
        elif manifest["schema_version"] == 3 and manifest["provider"] == "agy":
            command = [
                *manifest["route_contract"]["argv_prefix"],
                "--mode",
                "plan",
                "--sandbox",
            ]
        elif manifest["provider"] == "claude":
            command = ["claude", "-p", "--output-format", "json", "--tools="]
        else:
            command = ["agy", "--mode", "plan", "--sandbox"]
        snapshot = {
            "head": self.head,
            "commit_bound": True,
            "context_count": len(packet["context"]),
            "worktree_clean_required": False,
        }
        receipt = {
            "schema_version": manifest["schema_version"],
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
            "runner_sha256": manifest["runner_sha256"],
            "prompt_sha256": competition._sha256_bytes(prompt),
            "provider_version": "test-provider 1.0",
            "command_shape": command,
            "provider_cwd_kind": "isolated_provider_workspace",
            "command_sha256": competition._sha256_json(command),
            "prompt_in_argv": False,
            "returncode": 0,
            "runtime_seconds": 1.0,
            "stdout_sha256": "3" * 64,
            "stderr_sha256": "4" * 64,
            "before": snapshot,
            "after": dict(snapshot),
            "candidate": candidate,
            "authority": "advisory_only",
            "automatic_apply": False,
            "automatic_commit": False,
            "automatic_merge": False,
            "automatic_deploy": False,
            "does_not_establish": [
                "correctness", "test_pass", "review_pass", "merge_readiness", "preferred_candidate"
            ],
        }
        if manifest["schema_version"] >= 2:
            receipt["budget_contract"] = manifest["budget_contract"]
        if manifest["schema_version"] == 3:
            receipt["route_contract"] = manifest["route_contract"]
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
        with mock.patch.object(
            competition.coding_router,
            "select_contrast_routes",
            side_effect=lambda *args, **kwargs: self._route_selection(
                max_candidates=kwargs["max_candidates"],
                allow_paid=kwargs["allow_paid"],
            ),
        ):
            competitive = competition.grabowski_agent_execution_route(
                task_kind="code",
                changed_file_estimate=12,
                expected_duration_minutes=180,
                novelty="high",
                risk_flags=["security", "concurrency"],
                user_requested_external=True,
                available_external_agents=["codex", "claude"],
                decision_fork=True,
                architecture_hypotheses=2,
                paid_execution_authorized=True,
            )
        self.assertEqual(competitive["execution_mode"], "direct_operator")
        self.assertEqual(competitive["risk_tier"], "R3")
        self.assertEqual(competitive["route_policy_version"], "direct-first-routing-v3.0")
        self.assertFalse(competitive["automatic_winner_selection"])
        self.assertTrue(competitive["direct_implementation_required"])
        self.assertTrue(competitive["external_primary_writer_forbidden"])
        self.assertFalse(competitive["full_workspace"])
        self.assertEqual(len(competitive["external_candidates"]), 2)
        self.assertEqual(
            [item["route_id"] for item in competitive["external_route_candidates"]],
            ["codex-sol-high", "claude-fable-5-contrast-high"],
        )
        self.assertTrue(competitive["external_route_candidates"][1]["paid_only"])


    def test_route_v21_keeps_routine_code_out_of_full_workspace(self) -> None:
        four_files = competition.grabowski_agent_execution_route(
            task_kind="code",
            changed_file_estimate=4,
            expected_duration_minutes=30,
            novelty="low",
            available_external_agents=["claude"],
        )
        six_files = competition.grabowski_agent_execution_route(
            task_kind="code",
            changed_file_estimate=6,
            expected_duration_minutes=55,
            novelty="low",
            available_external_agents=["claude"],
        )
        self.assertEqual(four_files["execution_mode"], "direct_operator")
        self.assertEqual(six_files["execution_mode"], "direct_operator")
        self.assertEqual(four_files["risk_tier"], "R1")
        self.assertFalse(four_files["full_workspace"])

    def test_route_v21_contrast_and_competition_require_distinct_gates(self) -> None:
        base = dict(
            task_kind="code",
            changed_file_estimate=18,
            expected_duration_minutes=180,
            novelty="high",
            risk_flags=["schema"],
            user_requested_external=True,
            available_external_agents=["codex", "claude"],
        )
        with mock.patch.object(
            competition.coding_router,
            "select_contrast_routes",
            side_effect=lambda *args, **kwargs: self._route_selection(
                max_candidates=kwargs["max_candidates"],
                allow_paid=kwargs["allow_paid"],
            ),
        ):
            contrast = competition.grabowski_agent_execution_route(**base)
            competition_route = competition.grabowski_agent_execution_route(
                **base,
                decision_fork=True,
                architecture_hypotheses=2,
                paid_execution_authorized=True,
            )
        self.assertEqual(contrast["execution_mode"], "direct_operator")
        self.assertEqual(len(contrast["external_candidates"]), 1)
        self.assertEqual(competition_route["execution_mode"], "direct_operator")
        self.assertEqual(len(competition_route["external_candidates"]), 2)

    def test_parallelization_candidate_does_not_authorize_or_change_live_route(self) -> None:
        kwargs = dict(
            task_kind="code",
            changed_file_estimate=18,
            expected_duration_minutes=240,
            novelty="high",
            risk_flags=["schema"],
            available_external_agents=[],
        )
        baseline = competition.grabowski_agent_execution_route(**kwargs)
        candidate = competition.grabowski_agent_execution_route(
            **kwargs, parallelization_candidate=True
        )
        self.assertEqual(candidate["score"], baseline["score"])
        self.assertEqual(candidate["execution_mode"], baseline["execution_mode"])
        self.assertFalse(
            candidate["parallel_writer_pilot"]["eligible_for_assessment"]
        )
        self.assertIn(
            "direct-first policy",
            candidate["parallel_writer_pilot"]["assessment_blockers"][0],
        )
        self.assertFalse(
            candidate["parallel_writer_pilot"]["execution_authorized"]
        )
        self.assertFalse(
            candidate["parallel_writer_pilot"]["workspace_group_implemented"]
        )

    def test_legacy_parallel_alias_is_safe_and_conflicts_fail_closed(self) -> None:
        legacy = competition.grabowski_agent_execution_route(
            task_kind="code",
            changed_file_estimate=4,
            expected_duration_minutes=30,
            novelty="low",
            parallel_work=True,
            available_external_agents=[],
        )
        explicit = competition.grabowski_agent_execution_route(
            task_kind="code",
            changed_file_estimate=4,
            expected_duration_minutes=30,
            novelty="low",
            concurrent_external_activity=True,
            available_external_agents=[],
        )
        self.assertEqual(legacy["recommendation_id"], explicit["recommendation_id"])
        with self.assertRaisesRegex(
            competition.AgentCompetitionError, "disagree"
        ):
            competition.grabowski_agent_execution_route(
                task_kind="code",
                changed_file_estimate=4,
                expected_duration_minutes=30,
                novelty="low",
                parallel_work=True,
                concurrent_external_activity=False,
                available_external_agents=[],
            )

    def test_route_shadow_calibration_never_changes_live_route_or_recommendation_id(self) -> None:
        kwargs = dict(
            task_kind="code",
            changed_file_estimate=5,
            expected_duration_minutes=60,
            novelty="medium",
            risk_flags=[],
            available_external_agents=["claude"],
        )
        baseline = competition.grabowski_agent_execution_route(**kwargs)
        with mock.patch.object(
            competition,
            "_workspace_route_shadow_calibration",
            return_value={
                "schema_version": 1,
                "mode": "shadow_only",
                "eligible": True,
                "route_summaries": [
                    {"route": "isolated_worktree", "closed_success_ratio": 1.0},
                    {"route": "full_workspace", "closed_success_ratio": 0.5},
                ],
                "applied_to_live_route": False,
                "execution_authorized": False,
            },
        ):
            calibrated = competition.grabowski_agent_execution_route(**kwargs)
        self.assertEqual(calibrated["execution_mode"], baseline["execution_mode"])
        self.assertEqual(calibrated["recommendation_id"], baseline["recommendation_id"])
        self.assertTrue(calibrated["shadow_calibration"]["eligible"])
        self.assertFalse(calibrated["shadow_calibration"]["applied_to_live_route"])
        self.assertFalse(calibrated["shadow_calibration"]["execution_authorized"])

    def test_route_shadow_calibration_counts_only_usable_route_records(self) -> None:
        import grabowski_agent_workspace_observer as workspace_observer

        self.patchers.pop().stop()
        input_facts = {
            "task_kind": "code",
            "changed_file_estimate": 7,
            "expected_duration_minutes": 90,
            "novelty": "medium",
            "risk_flags": [],
            "connector_instability": False,
            "concurrent_external_activity": False,
            "parallelization_candidate": False,
            "decision_fork": False,
            "architecture_hypotheses": 1,
            "user_requested_external": False,
            "available_external_agents": [],
        }
        risk_tier = competition.workspace._route_decision(input_facts)["risk_tier"]
        records = []
        for index in range(5):
            route_evidence = {
                "schema_version": 2,
                "route_policy_version": competition.workspace.ROUTE_POLICY_VERSION,
                "risk_tier": risk_tier,
                "input_facts": dict(input_facts),
            }
            if index < 4:
                route_evidence["actual_route"] = (
                    "full_workspace" if index < 2 else "workspace_with_contrast"
                )
            records.append({
                "route_evidence": route_evidence,
                "closed": True,
                "closure_outcome": "successful",
                "workspace_friction_classes": [],
                "quality_signal_classes": [],
                "timing": {"close_complete_seconds": float(index + 1)},
                "report_sha256": f"{index + 1:064x}",
            })
        snapshot = {
            "integrity_valid": True,
            "snapshot_sha256": "a" * 64,
            "current_cohort": {"cohort_key": "release:test"},
            "friction_fingerprint_sha256": "b" * 64,
            "route_records": records,
        }
        with mock.patch.object(
            workspace_observer, "workspace_metrics_snapshot", return_value=snapshot
        ):
            result = competition._workspace_route_shadow_calibration(
                input_facts,
                "full_workspace",
            )
        self.assertEqual(result["comparable_workspace_count"], 4)
        self.assertEqual(result["discarded_record_count"], 1)
        self.assertEqual(len(result["route_summaries"]), 2)
        self.assertFalse(result["eligible"])
        self.assertFalse(result["applied_to_live_route"])

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
        self.assertEqual(packet["runner_sha256"], manifest["runner_sha256"])
        self.assertEqual(
            hashlib.sha256((directory / "runner.py").read_bytes()).hexdigest(),
            manifest["runner_sha256"],
        )
        self.assertEqual((directory / "runner.py").stat().st_mode & 0o777, 0o600)
        self.assertEqual((directory / "provider-workspace").stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / "packet.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((directory / "start-intent.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((directory / "manifest.json").stat().st_mode & 0o777, 0o600)

    def test_manifest_rejects_tampered_frozen_runner(self) -> None:
        started = self._start()
        runner = self.state / started["competition_id"] / "runner.py"
        runner.write_bytes(runner.read_bytes() + b"\n# tampered\n")
        with self.assertRaisesRegex(competition.AgentCompetitionError, "runner hash"):
            competition._validated_manifest(started["competition_id"])

    def test_receipt_rejects_unexpected_provider_workspace_file(self) -> None:
        started = self._start()
        self._write_receipt(started["competition_id"], changed_paths=[], risks=[], tests=[])
        workspace_path = self.state / started["competition_id"] / "provider-workspace"
        (workspace_path / "unexpected.txt").write_text("mutation", encoding="utf-8")
        with self.assertRaisesRegex(competition.AgentCompetitionError, "workspace contents"):
            competition._receipt(started["competition_id"])

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
            first = self._authorized_start(**kwargs)
            second = self._authorized_start(**kwargs)
        self.assertFalse(first["already_started"])
        self.assertTrue(second["already_started"])
        self.assertEqual(first["competition_id"], second["competition_id"])
        self.assertEqual(start.call_count, 1)
        changed = dict(kwargs)
        changed["primary_summary"] = "different"
        with self.assertRaisesRegex(competition.AgentCompetitionError, "different competition contract"):
            self._authorized_start(**changed)

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
        runner_bytes = competition._load_regular_bytes(
            competition.RUNNER,
            label="test runner",
            max_bytes=competition.MAX_RUNNER_BYTES,
            required_mode=None,
        )
        contract = {
            "request_id": request_id,
            "provider": "claude",
            "mode": "competitor",
            "repository": str(self.repo),
            "expected_head": self.head,
            "task_sha256": task_sha256,
            "runner_sha256": competition._sha256_bytes(runner_bytes),
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
                self._authorized_start(
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
                self._authorized_start(
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
                self._authorized_start(
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
                self._authorized_start(
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
            self._authorized_start(
                request_id="test-sensitive-scope",
                provider="claude",
                mode="competitor",
                repository=str(self.repo),
                expected_head=head,
                task="task",
                allowed_paths=["secrets"],
                context_paths=["secrets/note.txt"],
            )

    def test_private_json_reader_detects_in_place_mutation(self) -> None:
        directory = self.state / "read-race"
        directory.mkdir(mode=0o700)
        path = directory / "state.json"
        competition._atomic_json(path, {"value": "x" * 1000})
        original_read = competition.os.read
        mutated = False

        def mutate_after_read(descriptor, size):
            nonlocal mutated
            chunk = original_read(descriptor, size)
            if not mutated:
                mutated = True
                with path.open("ab") as handle:
                    handle.write(b" ")
            return chunk

        with mock.patch.object(competition.os, "read", side_effect=mutate_after_read):
            with self.assertRaisesRegex(competition.AgentCompetitionError, "changed while being read"):
                competition._load_private_json(path, label="race state")

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
        with self.assertRaisesRegex(competition.AgentCompetitionError, "cannot open candidate receipt|bounded regular file"):
            competition._receipt(started["competition_id"])

    def test_receipt_symlink_to_regular_file_fails_closed(self) -> None:
        started = self._start()
        directory = self.state / started["competition_id"]
        target = directory / "other-receipt.json"
        target.write_text("{}\n", encoding="utf-8")
        target.chmod(0o600)
        (directory / "receipt.json").symlink_to(target)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "cannot open candidate receipt|bounded regular file"):
            competition._receipt(started["competition_id"])

    def test_receipt_shape_rejects_missing_required_key_even_with_optional_key(self) -> None:
        started = self._start()
        receipt = self._write_receipt(
            started["competition_id"], changed_paths=["src/sample.py"], risks=[], tests=[]
        )
        path = self.state / started["competition_id"] / "receipt.json"
        path.unlink()
        del receipt["before"]
        receipt["total_cost_usd"] = 0.25
        receipt["receipt_sha256"] = competition._sha256_json(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        competition._atomic_json(path, receipt)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "receipt shape"):
            competition._receipt(started["competition_id"])

    def test_receipt_shape_accepts_declared_optional_fields(self) -> None:
        started = self._start()
        receipt = self._write_receipt(
            started["competition_id"], changed_paths=["src/sample.py"], risks=[], tests=[]
        )
        path = self.state / started["competition_id"] / "receipt.json"
        path.unlink()
        receipt["total_cost_usd"] = 0.25
        receipt["output_wrapper"] = {
            "kind": "none",
            "discarded_prefix_bytes": 0,
            "discarded_suffix_bytes": 0,
            "discarded_wrapper_sha256": competition._sha256_bytes(b""),
        }
        receipt["receipt_sha256"] = competition._sha256_json(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        competition._atomic_json(path, receipt)
        validated = competition._receipt(started["competition_id"])
        self.assertEqual(validated["total_cost_usd"], 0.25)
        self.assertEqual(validated["output_wrapper"]["kind"], "none")

    def test_receipt_shape_rejects_unknown_extra_field(self) -> None:
        started = self._start()
        receipt = self._write_receipt(
            started["competition_id"], changed_paths=["src/sample.py"], risks=[], tests=[]
        )
        path = self.state / started["competition_id"] / "receipt.json"
        path.unlink()
        receipt["unexpected"] = "value"
        receipt["receipt_sha256"] = competition._sha256_json(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        competition._atomic_json(path, receipt)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "receipt shape"):
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

    def test_self_hashed_receipt_cannot_weaken_provider_isolation(self) -> None:
        started = self._start()
        receipt = self._write_receipt(
            started["competition_id"], changed_paths=["src/sample.py"], risks=[], tests=[]
        )
        path = self.state / started["competition_id"] / "receipt.json"
        path.unlink()
        receipt["provider_cwd_kind"] = "repository"
        receipt["receipt_sha256"] = competition._sha256_json(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        competition._atomic_json(path, receipt)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "provider isolation"):
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

    def test_compare_requires_exactly_two_candidates(self) -> None:
        with self.assertRaisesRegex(competition.AgentCompetitionError, "exactly 2"):
            competition.grabowski_agent_competition_compare(["one", "two", "three"])

    def test_compare_emits_consensus_and_divergence_without_winner(self) -> None:
        first = self._start(provider="claude", mode="competitor", task="same task")
        second = self._start(provider="agy", mode="contrast", task="same task")
        self._write_receipt(
            first["competition_id"],
            changed_paths=["src/sample.py", "tests/test_sample.py"],
            risks=["race", "left risk"],
            tests=["unit test", "left test"],
        )
        self._write_receipt(
            second["competition_id"],
            changed_paths=["src/sample.py"],
            risks=["race", "right risk"],
            tests=["unit test", "right test"],
        )
        result = competition.grabowski_agent_competition_compare([first["competition_id"], second["competition_id"]])
        self.assertEqual(result["consensus"]["changed_paths"], ["src/sample.py"])
        self.assertEqual(result["divergence"]["changed_paths"], ["tests/test_sample.py"])
        self.assertFalse(result["winner_selected"])
        self.assertFalse(result["automatic_apply"])
        self.assertEqual(result["schema_version"], 2)
        self.assertIn("unit test", result["consensus"]["proposed_tests"])
        self.assertIn(
            "left risk",
            result["divergence"]["unique_risks_by_candidate"][first["competition_id"]],
        )
        self.assertIn(
            "right test",
            result["divergence"]["unique_tests_by_candidate"][second["competition_id"]],
        )


    def test_default_zero_budget_blocks_before_provider_task_start(self) -> None:
        with mock.patch.object(competition.tasks, "grabowski_task_start") as start:
            with self.assertRaisesRegex(competition.AgentCompetitionError, "legacy provider-only execution"):
                competition.grabowski_agent_competition_start(
                    request_id="zero-cost-default",
                    provider="claude",
                    mode="competitor",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task="Review sample",
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py"],
                    timeout_seconds=120,
                )
        start.assert_not_called()


    def test_route_bound_codex_start_uses_zero_budget_and_schema3(self) -> None:
        contract = self._route_contract("codex-sol-high")
        with (
            mock.patch.object(
                competition.coding_router,
                "contrast_route_execution_contract",
                return_value=contract,
            ),
            mock.patch.object(
                competition.tasks,
                "grabowski_task_start",
                return_value=self._task_start("task-codex-route"),
            ) as start,
        ):
            result = competition.grabowski_agent_competition_start(
                request_id="codex-route-zero",
                provider="codex",
                mode="contrast",
                repository=str(self.repo),
                expected_head=self.head,
                task="Contrast sample",
                allowed_paths=["src", "tests"],
                context_paths=["src/sample.py"],
                timeout_seconds=120,
                max_budget_usd=0,
                route_id="codex-sol-high",
            )
        packet = competition._validated_packet(result["competition_id"])
        self.assertEqual(packet["schema_version"], 3)
        self.assertEqual(packet["route_contract"]["route_id"], "codex-sol-high")
        self.assertEqual(packet["budget_contract"]["requested_max_usd"], 0)
        self.assertFalse(packet["budget_contract"]["paid_execution_authorized"])
        self.assertEqual(result["route_id"], "codex-sol-high")
        start.assert_called_once()

    def test_route_bound_codex_receipt_preserves_route_and_zero_budget_binding(self) -> None:
        contract = self._route_contract("codex-sol-high")
        with (
            mock.patch.object(
                competition.coding_router,
                "contrast_route_execution_contract",
                return_value=contract,
            ),
            mock.patch.object(
                competition.tasks,
                "grabowski_task_start",
                return_value=self._task_start("task-codex-receipt"),
            ),
        ):
            started = competition.grabowski_agent_competition_start(
                request_id="codex-route-receipt",
                provider="codex",
                mode="contrast",
                repository=str(self.repo),
                expected_head=self.head,
                task="Contrast sample",
                allowed_paths=["src", "tests"],
                context_paths=["src/sample.py"],
                timeout_seconds=120,
                max_budget_usd=0,
                route_id="codex-sol-high",
            )
        self._write_receipt(
            started["competition_id"], changed_paths=[], risks=[], tests=[]
        )
        manifest = competition._validated_manifest(started["competition_id"])
        receipt = competition._receipt(started["competition_id"], manifest)
        self.assertIsNotNone(receipt)
        assert receipt is not None
        self.assertEqual(receipt["schema_version"], 3)
        self.assertEqual(receipt["route_contract"], contract)
        self.assertEqual(receipt["budget_contract"]["requested_max_usd"], 0)
        self.assertFalse(receipt["budget_contract"]["paid_execution_authorized"])

    def test_route_bound_agy_receipt_preserves_route_and_zero_budget_binding(self) -> None:
        contract = self._route_contract("agy-gemini-flash-medium")
        with (
            mock.patch.object(
                competition.coding_router,
                "contrast_route_execution_contract",
                return_value=contract,
            ),
            mock.patch.object(
                competition.tasks,
                "grabowski_task_start",
                return_value=self._task_start("task-agy-receipt"),
            ),
        ):
            started = competition.grabowski_agent_competition_start(
                request_id="agy-route-receipt",
                provider="agy",
                mode="contrast",
                repository=str(self.repo),
                expected_head=self.head,
                task="Contrast sample",
                allowed_paths=["src", "tests"],
                context_paths=["src/sample.py"],
                timeout_seconds=120,
                max_budget_usd=0,
                route_id="agy-gemini-flash-medium",
            )
        self._write_receipt(
            started["competition_id"], changed_paths=[], risks=[], tests=[]
        )
        manifest = competition._validated_manifest(started["competition_id"])
        receipt = competition._receipt(started["competition_id"], manifest)
        self.assertIsNotNone(receipt)
        assert receipt is not None
        self.assertEqual(receipt["schema_version"], 3)
        self.assertEqual(receipt["route_contract"], contract)
        self.assertEqual(receipt["budget_contract"]["requested_max_usd"], 0)
        self.assertFalse(receipt["budget_contract"]["paid_execution_authorized"])

    def test_route_bound_fable_requires_paid_authorization_and_positive_policy_cap(self) -> None:
        with mock.patch.object(
            competition.coding_router,
            "contrast_route_execution_contract",
            side_effect=competition.coding_router.CodingAgentRouterError(
                "paid-only route requires explicit paid execution authorization"
            ),
        ):
            with self.assertRaisesRegex(competition.AgentCompetitionError, "paid-only route"):
                competition.grabowski_agent_competition_start(
                    request_id="fable-no-paid-auth",
                    provider="claude",
                    mode="contrast",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task="Contrast sample",
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py"],
                    max_budget_usd=1,
                    route_id="claude-fable-5-contrast-high",
                )

        contract = self._route_contract(
            "claude-fable-5-contrast-high", paid=True
        )
        with (
            mock.patch.object(
                competition.coding_router,
                "contrast_route_execution_contract",
                return_value=contract,
            ),
            mock.patch.dict(
                os.environ,
                {competition.EXTERNAL_PROVIDER_BUDGET_CAP_ENV: "0"},
                clear=False,
            ),
        ):
            with self.assertRaisesRegex(competition.AgentCompetitionError, "policy cap of 0 USD"):
                competition.grabowski_agent_competition_start(
                    request_id="fable-zero-cap",
                    provider="claude",
                    mode="contrast",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task="Contrast sample",
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py"],
                    max_budget_usd=1,
                    route_id="claude-fable-5-contrast-high",
                    paid_execution_authorized=True,
                )

    def test_positive_budget_is_blocked_by_zero_runtime_policy_cap(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {competition.EXTERNAL_PROVIDER_BUDGET_CAP_ENV: "0"},
                clear=False,
            ),
            mock.patch.object(competition.tasks, "grabowski_task_start") as start,
        ):
            with self.assertRaisesRegex(competition.AgentCompetitionError, "policy cap of 0 USD"):
                competition.grabowski_agent_competition_start(
                    request_id="positive-budget-zero-cap",
                    provider="claude",
                    mode="competitor",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task="Review sample",
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py"],
                    timeout_seconds=120,
                    max_budget_usd=1.0,
                    require_hard_budget=True,
                )
        start.assert_not_called()

    def test_invalid_runtime_budget_cap_fails_closed(self) -> None:
        with mock.patch.dict(
            os.environ,
            {competition.EXTERNAL_PROVIDER_BUDGET_CAP_ENV: "not-a-number"},
            clear=False,
        ):
            with self.assertRaisesRegex(competition.AgentCompetitionError, "must be a finite number"):
                competition.grabowski_agent_competition_start(
                    request_id="invalid-runtime-cap",
                    provider="claude",
                    mode="competitor",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task="Review sample",
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py"],
                    timeout_seconds=120,
                    max_budget_usd=1.0,
                    require_hard_budget=True,
                )

    def test_agy_budget_contract_is_explicit_and_hard_requirement_fails_closed(self) -> None:
        started = self._start(provider="agy")
        self.assertFalse(started["budget_contract"]["hard_limit"])
        self.assertEqual(started["budget_contract"]["enforcement"], "not_supported_by_provider")
        self.assertTrue(started["budget_contract"]["timeout_is_not_budget"])
        with self.assertRaisesRegex(competition.AgentCompetitionError, "cannot enforce a hard USD budget"):
            self._authorized_start(
                request_id="agy-hard-budget",
                provider="agy",
                mode="contrast",
                repository=str(self.repo),
                expected_head=self.head,
                task="Review sample",
                allowed_paths=["src", "tests"],
                context_paths=["src/sample.py"],
                timeout_seconds=120,
                require_hard_budget=True,
            )

    def test_task_start_exception_reconciles_one_exact_persistent_task(self) -> None:
        request_id = "reconcile-exact"

        def task_list(*, limit=20, state=None, view="minimal", cursor=None, fields=None):
            del state, fields
            self.assertEqual(limit, competition.START_RECONCILE_PAGE_LIMIT)
            self.assertEqual(view, "standard")
            self.assertIsNone(cursor)
            directories = [item for item in self.state.iterdir() if item.is_dir()]
            self.assertEqual(len(directories), 1)
            directory = directories[0]
            intent = json.loads((directory / "start-intent.json").read_text())
            return {
                "tasks": [{
                    "task_id": "reconciled-task",
                    "host": "heim-pc",
                    "unit": "grabowski-task-reconciled-task-a1.service",
                    "attempt": 1,
                    "state": "running",
                    "resume_policy": "never",
                    "argv_sha256": intent["command_sha256"],
                    "cwd": str(directory),
                    "resource_keys": [f"path:{directory}"],
                    "created_at_unix": intent["created_at_unix"],
                }],
                "pagination": {"has_more": False, "next_cursor": None},
            }

        with (
            mock.patch.object(competition.tasks, "grabowski_task_start", side_effect=RuntimeError("transport lost")),
            mock.patch.object(competition.tasks, "grabowski_task_list", side_effect=task_list),
        ):
            result = self._authorized_start(
                request_id=request_id,
                provider="claude",
                mode="competitor",
                repository=str(self.repo),
                expected_head=self.head,
                task="Improve sample",
                allowed_paths=["src", "tests"],
                context_paths=["src/sample.py"],
                timeout_seconds=120,
            )
        self.assertTrue(result["start_reconciled"])
        self.assertEqual(result["task_id"], "reconciled-task")
        manifest = competition._validated_manifest(result["competition_id"])
        self.assertEqual(manifest["task_id"], "reconciled-task")

    def test_ambiguous_task_reconciliation_remains_fail_closed(self) -> None:
        request_id = "reconcile-ambiguous"
        task = "Improve sample"

        def task_list(*, limit=20, state=None, view="minimal", cursor=None, fields=None):
            del state, fields
            self.assertEqual(limit, competition.START_RECONCILE_PAGE_LIMIT)
            self.assertEqual(view, "standard")
            self.assertIsNone(cursor)
            directory = next(item for item in self.state.iterdir() if item.is_dir())
            intent = json.loads((directory / "start-intent.json").read_text())
            base = {
                "host": "heim-pc",
                "unit": "u",
                "attempt": 1,
                "state": "running",
                "resume_policy": "never",
                "argv_sha256": intent["command_sha256"],
                "cwd": str(directory),
                "resource_keys": [f"path:{directory}"],
                "created_at_unix": intent["created_at_unix"],
            }
            return {
                "tasks": [{**base, "task_id": "one"}, {**base, "task_id": "two"}],
                "pagination": {"has_more": False, "next_cursor": None},
            }

        with (
            mock.patch.object(competition.tasks, "grabowski_task_start", side_effect=RuntimeError("transport lost")),
            mock.patch.object(competition.tasks, "grabowski_task_list", side_effect=task_list),
        ):
            with self.assertRaisesRegex(RuntimeError, "transport lost"):
                self._authorized_start(
                    request_id=request_id,
                    provider="claude",
                    mode="competitor",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task=task,
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py"],
                    timeout_seconds=120,
                )
            identifier = competition._competition_id(
                "claude", "competitor", competition._sha256_bytes(task.encode()), request_id
            )
            status = competition.grabowski_agent_competition_status(identifier)
        self.assertEqual(status["start_reconciliation"]["state"], "ambiguous_matches")
        self.assertTrue(status["retry_blocked"])
        self.assertEqual(status["lifecycle_state"], "task_start_outcome_unknown")

    def test_reconciliation_uses_standard_paginated_task_contract(self) -> None:
        started = self._start()
        identifier = started["competition_id"]
        directory = self.state / identifier
        intent = competition._validated_start_intent(identifier)
        expected = {
            "task_id": "exact-on-page-two",
            "host": "heim-pc",
            "unit": "u",
            "attempt": 1,
            "state": "running",
            "resume_policy": "never",
            "argv_sha256": intent["command_sha256"],
            "cwd": str(directory),
            "resource_keys": [f"path:{directory}"],
            "created_at_unix": intent["created_at_unix"],
        }
        calls: list[dict[str, object]] = []

        def task_list(*, limit=20, state=None, view="minimal", cursor=None, fields=None):
            del state, fields
            calls.append({"limit": limit, "view": view, "cursor": cursor})
            if cursor is None:
                return {
                    "tasks": [{
                        **expected,
                        "task_id": "newer-unrelated",
                        "argv_sha256": "f" * 64,
                        "created_at_unix": intent["created_at_unix"] + 1,
                    }],
                    "pagination": {"has_more": True, "next_cursor": "page-two"},
                }
            self.assertEqual(cursor, "page-two")
            return {
                "tasks": [expected, {**expected, "task_id": "older", "created_at_unix": intent["created_at_unix"] - 1}],
                "pagination": {"has_more": True, "next_cursor": "unused"},
            }

        with mock.patch.object(competition.tasks, "grabowski_task_list", side_effect=task_list):
            result = competition._start_reconciliation(identifier, intent)
        self.assertEqual(result["state"], "unique_match")
        self.assertEqual(result["matches"], ["exact-on-page-two"])
        self.assertEqual(
            calls,
            [
                {"limit": competition.START_RECONCILE_PAGE_LIMIT, "view": "standard", "cursor": None},
                {"limit": competition.START_RECONCILE_PAGE_LIMIT, "view": "standard", "cursor": "page-two"},
            ],
        )

    def test_path_policy_blocks_keys_and_generated_trees_without_tokenizer_false_positive(self) -> None:
        self.assertFalse(competition._path_is_sensitive("src/tokenizer.py"))
        self.assertFalse(competition._path_is_sensitive("src/token_count.py"))
        self.assertTrue(competition._path_is_sensitive("config/service-token.json"))
        self.assertTrue(competition._path_is_sensitive("certs/server.pem"))
        self.assertTrue(competition._path_is_sensitive("config/.env.production"))
        self.assertTrue(competition._path_has_default_forbidden_component("web/node_modules/pkg/index.js"))
        self.assertTrue(competition._path_has_default_forbidden_component("rust/target/debug/app"))
        self.assertTrue(competition._path_has_default_forbidden_component("frontend/build/assets/app.js"))

    def test_default_forbidden_allowed_scope_is_rejected(self) -> None:
        with self.assertRaisesRegex(competition.AgentCompetitionError, "default-forbidden allowed"):
            self._authorized_start(
                request_id="forbidden-tree",
                provider="claude",
                mode="competitor",
                repository=str(self.repo),
                expected_head=self.head,
                task="task",
                allowed_paths=["node_modules"],
                context_paths=["src/sample.py"],
            )

    def test_stale_competition_temp_cleanup_is_bounded_and_preserves_fresh_files(self) -> None:
        directory = self.state / "cleanup"
        directory.mkdir(mode=0o700)
        stale = directory / ".manifest.json.1234.aaaaaaaaaaaaaaaa.tmp"
        fresh = directory / ".packet.json.1234.bbbbbbbbbbbbbbbb.tmp"
        stale.write_text("old", encoding="utf-8")
        fresh.write_text("new", encoding="utf-8")
        stale.chmod(0o600)
        fresh.chmod(0o600)
        os.utime(stale, (0, 0))
        os.utime(fresh, (1000, 1000))
        result = competition._cleanup_stale_competition_temps(directory, now_unix=1000)
        self.assertEqual(result, {"inspected": 2, "removed": 1, "errors": 0})
        self.assertFalse(stale.exists())
        self.assertTrue(fresh.exists())

    def test_manifest_publish_readback_prevents_cancel_of_visible_bound_manifest(self) -> None:
        original_atomic = competition._atomic_json

        def publish_then_fail(path, value):
            result = original_atomic(path, value)
            if path.name == "manifest.json":
                raise OSError("directory fsync uncertain")
            return result

        with (
            mock.patch.object(competition, "_atomic_json", side_effect=publish_then_fail),
            mock.patch.object(
                competition.tasks,
                "grabowski_task_start",
                return_value=self._task_start("visible-manifest-task"),
            ),
            mock.patch.object(competition.tasks, "grabowski_task_cancel") as cancel,
        ):
            result = self._authorized_start(
                request_id="manifest-readback",
                provider="claude",
                mode="competitor",
                repository=str(self.repo),
                expected_head=self.head,
                task="Improve sample",
                allowed_paths=["src", "tests"],
                context_paths=["src/sample.py"],
                timeout_seconds=120,
            )
        self.assertTrue(result["manifest_publish_readback_recovered"])
        cancel.assert_not_called()

    def test_status_uses_deterministic_provider_phase(self) -> None:
        started = self._start()
        with mock.patch.object(
            competition.tasks,
            "grabowski_task_status",
            return_value={"task_id": started["task_id"], "state": "running", "unit": "u"},
        ):
            status = competition.grabowski_agent_competition_status(started["competition_id"])
        self.assertEqual(status["lifecycle_state"], "provider_running")
        self.assertEqual(status["phase"], "provider_execution")

    def test_high_novelty_security_alone_does_not_force_external_competition(self) -> None:
        result = competition.grabowski_agent_execution_route(
            task_kind="code",
            changed_file_estimate=1,
            expected_duration_minutes=5,
            novelty="high",
            risk_flags=["security"],
            available_external_agents=["claude", "agy"],
        )
        self.assertEqual(result["execution_mode"], "direct_operator")
        self.assertEqual(result["external_candidates"], [])


    def test_manifest_rejects_packet_schema_mismatch_and_tampered_context_hash(self) -> None:
        started = self._start()
        directory = self.state / started["competition_id"]
        packet_path = directory / "packet.json"
        manifest_path = directory / "manifest.json"
        packet = json.loads(packet_path.read_text())
        manifest = json.loads(manifest_path.read_text())
        packet["context"][0]["sha256"] = "f" * 64
        packet["packet_sha256"] = competition._sha256_json(
            {key: value for key, value in packet.items() if key != "packet_sha256"}
        )
        manifest["packet_sha256"] = packet["packet_sha256"]
        manifest["manifest_sha256"] = competition._sha256_json(
            {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        )
        packet_path.unlink()
        manifest_path.unlink()
        competition._atomic_json(packet_path, packet)
        competition._atomic_json(manifest_path, manifest)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "hash-mismatched"):
            competition._validated_manifest(started["competition_id"])

    def test_v2_receipt_rejects_budget_tampering_and_excess_reported_cost(self) -> None:
        started = self._start(provider="claude")
        identifier = started["competition_id"]
        receipt = self._write_receipt(
            identifier,
            changed_paths=["src/sample.py"],
            risks=["budget drift"],
            tests=["budget contract test"],
        )
        path = self.state / identifier / "receipt.json"
        receipt["budget_contract"] = dict(receipt["budget_contract"])
        receipt["budget_contract"]["requested_max_usd"] = 3.0
        receipt["receipt_sha256"] = competition._sha256_json(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        path.unlink()
        competition._atomic_json(path, receipt)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "budget"):
            competition._receipt(identifier)

        path.unlink()
        receipt["budget_contract"] = started["budget_contract"]
        receipt["total_cost_usd"] = 3.0
        receipt["receipt_sha256"] = competition._sha256_json(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        competition._atomic_json(path, receipt)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "total_cost_usd"):
            competition._receipt(identifier)

    def test_reconciliation_rejects_wrong_host_and_pre_intent_task(self) -> None:
        started = self._start()
        identifier = started["competition_id"]
        directory = self.state / identifier
        intent = competition._validated_start_intent(identifier)
        wrong = {
            "task_id": "wrong-host",
            "host": "other-host",
            "unit": "u",
            "attempt": 1,
            "state": "running",
            "resume_policy": "never",
            "argv_sha256": intent["command_sha256"],
            "cwd": str(directory),
            "resource_keys": [f"path:{directory}"],
            "created_at_unix": intent["created_at_unix"],
        }
        early = {**wrong, "task_id": "too-early", "host": "heim-pc", "created_at_unix": intent["created_at_unix"] - 1}
        with mock.patch.object(
            competition.tasks,
            "grabowski_task_list",
            return_value={
                "tasks": [wrong, early],
                "pagination": {"has_more": False, "next_cursor": None},
            },
        ):
            result = competition._start_reconciliation(identifier, intent)
        self.assertEqual(result["state"], "no_match")
        self.assertEqual(result["matches"], [])


    def test_existing_v1_manifest_remains_idempotently_readable(self) -> None:
        started = self._start(provider="claude", mode="competitor", task="legacy task")
        identifier = started["competition_id"]
        directory = self.state / identifier
        packet_path = directory / "packet.json"
        intent_path = directory / "start-intent.json"
        manifest_path = directory / "manifest.json"
        packet = json.loads(packet_path.read_text())
        intent = json.loads(intent_path.read_text())
        manifest = json.loads(manifest_path.read_text())
        legacy_contract = {
            "request_id": packet["request_id"],
            "provider": packet["provider"],
            "mode": packet["mode"],
            "repository": packet["repository"],
            "expected_head": packet["expected_head"],
            "task_sha256": packet["task_sha256"],
            "runner_sha256": packet["runner_sha256"],
            "task": packet["task"],
            "allowed_paths": packet["allowed_paths"],
            "forbidden_paths": packet["forbidden_paths"],
            "context": [
                {"path": item["path"], "sha256": item["sha256"]}
                for item in packet["context"]
            ],
            "primary_summary": packet["primary_summary"],
            "timeout_seconds": 120,
            "max_budget_usd": 2.0,
        }
        legacy_fingerprint = competition._sha256_json(legacy_contract)
        packet["schema_version"] = 1
        packet.pop("budget_contract")
        packet["request_fingerprint"] = legacy_fingerprint
        packet["packet_sha256"] = competition._sha256_json(
            {key: value for key, value in packet.items() if key != "packet_sha256"}
        )
        intent["schema_version"] = 1
        intent.pop("created_at_unix")
        intent["request_fingerprint"] = legacy_fingerprint
        intent["packet_sha256"] = packet["packet_sha256"]
        intent["start_intent_sha256"] = competition._sha256_json(
            {key: value for key, value in intent.items() if key != "start_intent_sha256"}
        )
        manifest["schema_version"] = 1
        manifest.pop("budget_contract")
        manifest["request_fingerprint"] = legacy_fingerprint
        manifest["packet_sha256"] = packet["packet_sha256"]
        manifest["start_intent_sha256"] = intent["start_intent_sha256"]
        manifest["manifest_sha256"] = competition._sha256_json(
            {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        )
        for path, value in (
            (packet_path, packet),
            (intent_path, intent),
            (manifest_path, manifest),
        ):
            path.unlink()
            competition._atomic_json(path, value)
        with mock.patch.object(competition.tasks, "grabowski_task_start") as start:
            repeated = self._authorized_start(
                request_id="test-claude-competitor",
                provider="claude",
                mode="competitor",
                repository=str(self.repo),
                expected_head=self.head,
                task="legacy task",
                allowed_paths=["src", "tests"],
                context_paths=["src/sample.py", "tests/test_sample.py"],
                forbidden_paths=[],
                timeout_seconds=120,
            )
        start.assert_not_called()
        self.assertTrue(repeated["already_started"])
        self.assertIsNone(repeated["budget_contract"])
        self.assertEqual(competition._validated_manifest(identifier)["schema_version"], 1)


    def test_read_only_status_does_not_cleanup_stale_state_temps(self) -> None:
        started = self._start()
        directory = self.state / started["competition_id"]
        stale = directory / ".status.json.1234.aaaaaaaaaaaaaaaa.tmp"
        stale.write_text("old", encoding="utf-8")
        stale.chmod(0o600)
        os.utime(stale, (0, 0))
        with mock.patch.object(
            competition.tasks,
            "grabowski_task_status",
            return_value={"task_id": started["task_id"], "state": "running", "unit": "u"},
        ):
            status = competition.grabowski_agent_competition_status(started["competition_id"])
        self.assertEqual(status["phase"], "provider_execution")
        self.assertTrue(stale.exists())



    def test_route_recommendation_id_is_stable_and_trivial_boundary_is_explicit(self) -> None:
        kwargs = {
            "task_kind": "code",
            "changed_file_estimate": 8,
            "expected_duration_minutes": 90,
            "novelty": "high",
            "risk_flags": ["schema", "concurrency"],
            "connector_instability": True,
            "parallel_work": True,
            "parallelization_candidate": True,
            "available_external_agents": [],
        }
        first = competition.grabowski_agent_execution_route(**kwargs)
        second = competition.grabowski_agent_execution_route(**kwargs)
        self.assertEqual(first["recommendation_id"], second["recommendation_id"])
        self.assertRegex(first["recommendation_id"], r"^[0-9a-f]{64}$")
        self.assertEqual(first["input_facts"]["changed_file_estimate"], 8)
        self.assertTrue(first["input_facts"]["concurrent_external_activity"])
        self.assertNotIn("parallel_work", first["input_facts"])
        self.assertFalse(first["parallel_writer_pilot"]["execution_authorized"])
        self.assertFalse(first["trivial_work"])
        self.assertTrue(first["deviation_requires_reason"])
        trivial = competition.grabowski_agent_execution_route(
            task_kind="docs",
            changed_file_estimate=1,
            expected_duration_minutes=15,
            novelty="low",
            risk_flags=[],
            connector_instability=False,
            parallel_work=False,
            available_external_agents=[],
        )
        self.assertTrue(trivial["trivial_work"])


if __name__ == "__main__":
    unittest.main()
