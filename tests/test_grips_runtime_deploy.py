from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class _FakeFastMCP:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def tool(self, *args: object, **kwargs: object):
        del args, kwargs
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs: object) -> None:
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

import grabowski_grips as grips  # noqa: E402
import grabowski_self_deploy as real_deploy  # noqa: E402


class RuntimeDeployScheduleReceiptTests(unittest.TestCase):
    def test_scheduler_auto_source_non_object_preserves_unknown_mutation_outcome(
        self,
    ) -> None:
        preflight = {
            "resolution_mode": "scheduler-auto-source",
            "ready": True,
        }
        action = {
            "target": {
                "adapter": "grabowski-self",
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
            }
        }

        with patch.object(
            grips,
            "_runtime_deploy_expected_head",
            return_value="a" * 40,
        ), patch.object(
            grips,
            "_runtime_deploy_delay_seconds",
            return_value=8,
        ), patch.object(
            grips,
            "_runtime_deploy_source_parameters",
            return_value=(None, None),
        ), patch.object(
            grips,
            "_captain_runtime_deploy_target_errors",
            return_value=[],
        ), patch.object(
            grips,
            "_runtime_deploy_self_preflight",
            return_value=preflight,
        ), patch.object(
            grips,
            "_runtime_deploy_self_schedule",
            return_value=["not", "an", "object"],
        ):
            result = grips._run_captain_runtime_deploy(action, {})

        self.assertTrue(result["execution_attempted"])
        self.assertTrue(result["execution_invoked"])
        self.assertTrue(result["command_returned"])
        self.assertTrue(result["mutation_outcome_unknown"])
        self.assertTrue(result["local_mutation_outcome_unknown"])
        self.assertFalse(result["verification_passed"])
        self.assertIn(
            "runtime deploy scheduler returned non-object",
            result["verification_error"],
        )

    def test_bound_preflight_uses_scheduler_source_readback_after_race(self) -> None:
        expected = "a" * 40
        preflight = {
            "repository": "/home/alex/repos/grabowski",
            "runner": "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
            "job_root": "/home/alex/.local/state/grabowski/jobs",
            "job_prefix": "grabowski-job-",
            "source_kind": "canonical-main",
            "source_identity_sha256": "c" * 64,
            "ready": True,
        }
        source_repository = (
            "/home/alex/repos/.grabowski-deploy-worktrees/"
            "auto-current-main-aaaaaaaaaaaa-abc123def456"
        )
        source_readback = {
            "repository": source_repository,
            "runner": f"{source_repository}/tools/run_scheduled_deploy.py",
            "source_kind": "detached-worktree",
            "source_identity_sha256": "d" * 64,
            "source_lease_resource_key": f"path:{source_repository}",
            "source_lease_metadata_sha256": "e" * 64,
        }
        schedule = {
            "delay_seconds": 8,
            "unit": "grabowski-job-race00000001",
            "already_scheduled": False,
            "status_tool": "grabowski_job_status",
            "logs_tool": "grabowski_job_logs",
        }
        action = {
            "target": {
                "adapter": "grabowski-self",
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
            }
        }

        with patch.object(
            grips,
            "_runtime_deploy_expected_head",
            return_value=expected,
        ), patch.object(
            grips,
            "_runtime_deploy_delay_seconds",
            return_value=8,
        ), patch.object(
            grips,
            "_runtime_deploy_source_parameters",
            return_value=(None, None),
        ), patch.object(
            grips,
            "_captain_runtime_deploy_target_errors",
            return_value=[],
        ), patch.object(
            grips,
            "_runtime_deploy_self_preflight",
            return_value=preflight,
        ), patch.object(
            grips,
            "_runtime_deploy_self_schedule",
            return_value=schedule,
        ), patch.object(
            grips,
            "_runtime_deploy_self_schedule_source_preflight",
            return_value=source_readback,
        ) as source_check, patch.object(
            grips,
            "_runtime_deploy_self_expected_argv_sha256",
            return_value="f" * 64,
        ) as hash_check, patch.object(
            grips,
            "_runtime_deploy_schedule_errors",
            return_value=[],
        ):
            result = grips._run_captain_runtime_deploy(action, {})

        self.assertTrue(result["verification_passed"])
        self.assertEqual(source_readback, result["source_readback"])
        source_check.assert_called_once_with(schedule, expected)
        bound_preflight = hash_check.call_args.args[0]
        self.assertEqual(source_repository, bound_preflight["repository"])
        self.assertEqual("detached-worktree", bound_preflight["source_kind"])
        self.assertEqual("d" * 64, bound_preflight["source_identity_sha256"])



class RuntimeReleaseSourceAdmissionTests(unittest.TestCase):
    @staticmethod
    def _git_success(output: str) -> dict[str, object]:
        return {
            "returncode": 0,
            "timed_out": False,
            "stdout": output,
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    @staticmethod
    def _deployed() -> dict[str, object]:
        return {
            "release_id": "existing-protected-release",
            "repo_head": "a" * 40,
            "completion_status": "complete",
            "runtime_binding_valid": True,
            "artifact_integrity_valid": True,
            "provenance_valid": True,
        }

    @staticmethod
    def _serving() -> dict[str, object]:
        return {
            "matches_deployed_manifest": True,
            "process_release_id": "existing-protected-release",
            "process_repo_head": "a" * 40,
        }

    def test_critical_source_change_requires_authentic_release_admission(self) -> None:
        import grabowski_self_deploy as deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("src/grabowski_agent_role.py\x00tests/test_agent_role_grok.py\x00"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "release.*admission"):
                deploy._require_release_source_admission("b" * 40)

    def test_docs_only_delta_has_no_release_review_bypass_of_runtime_source(self) -> None:
        import grabowski_self_deploy as deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[self._git_success(""), self._git_success("docs/guide.md\x00")],
            ),
        ):
            record = deploy._require_release_source_admission("b" * 40)
        self.assertEqual("non-runtime-documentation", record["status"])

    def test_missing_serving_process_provenance_blocks(self) -> None:
        import grabowski_self_deploy as deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value={"matches_deployed_manifest": False}),
            patch.object(deploy, "_git_result") as git_read,
        ):
            with self.assertRaisesRegex(RuntimeError, "serving"):
                deploy._require_release_source_admission("b" * 40)
        git_read.assert_not_called()

    def test_direct_scheduler_rejects_before_github_or_local_mutation(self) -> None:
        import grabowski_self_deploy as deploy
        with (
            patch.object(deploy, "_require_release_source_admission", side_effect=RuntimeError("release admission missing")),
            patch.object(deploy, "_fresh_public_github_main") as remote,
            patch.object(deploy, "inflight_runtime_job_evidence") as inflight,
        ):
            with self.assertRaisesRegex(RuntimeError, "release admission missing"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    "b" * 40, local_mutation_tracker={}
                )
        remote.assert_not_called()
        inflight.assert_not_called()


    def test_missing_target_fetches_under_lock_then_readmits_before_effect(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        calls: list[str] = []

        def admit(head: str) -> dict[str, object]:
            self.assertEqual(expected, head)
            calls.append("admission")
            if calls.count("admission") == 1:
                raise deploy.DeploySchedulePreEffectRefusal(
                    "release admission blocked: source ancestry is unproved"
                )
            return {"status": "non-runtime-documentation"}

        def fetch(head: str, snapshot: dict, *, local_mutation_tracker: dict) -> None:
            self.assertEqual(expected, head)
            self.assertIs(snapshot["target_object_present"], False)
            self.assertEqual({}, local_mutation_tracker)
            calls.append("fetch")

        def stop_before_effect(head: str) -> str:
            calls.append("public-main-read")
            raise RuntimeError("stop before any effect")

        with (
            patch.object(deploy, "_require_release_source_admission", side_effect=admit),
            patch.object(
                deploy, "_canonical_main_refresh_candidate",
                return_value={"target_object_present": False},
            ),
            patch.object(deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(deploy, "_fetch_exact_release_admission_target", side_effect=fetch),
            patch.object(deploy, "_fresh_public_github_main", side_effect=stop_before_effect),
            patch.object(deploy, "inflight_runtime_job_evidence") as inflight,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as rootbroker,
        ):
            with self.assertRaisesRegex(RuntimeError, "stop before any effect"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker={}
                )
        self.assertEqual(
            ["admission", "fetch", "admission", "public-main-read"], calls
        )
        inflight.assert_not_called()
        rootbroker.assert_not_called()




    def test_target_imported_by_lock_winner_reuses_object_before_readmission(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        initial = {
            "canonical_repository": str(deploy.CANONICAL_REPOSITORY),
            "current_head": "a" * 40,
            "current_branch": "main",
            "target_head": expected,
            "origin_main": "c" * 40,
            "clean": True,
            "shallow": False,
            "target_object_present": False,
        }
        reobserved = {**initial, "target_object_present": True}
        events: list[str] = []

        def admission(head: str) -> dict:
            self.assertEqual(expected, head)
            events.append("admission")
            if events.count("admission") == 1:
                raise deploy.DeploySchedulePreEffectRefusal(
                    "release admission blocked: source ancestry is unproved"
                )
            return {"status": "non-runtime-documentation"}

        def stop_before_effect(head: str) -> str:
            self.assertEqual(expected, head)
            events.append("public-main")
            raise RuntimeError("stop before any effect")

        with (
            patch.object(deploy, "_require_release_source_admission", side_effect=admission),
            patch.object(deploy, "_canonical_main_refresh_candidate",
                         side_effect=[initial, reobserved]) as candidate,
            patch.object(deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
            patch.object(deploy, "_fresh_public_github_main", side_effect=stop_before_effect),
            patch.object(deploy, "inflight_runtime_job_evidence") as inflight,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as rootbroker,
        ):
            with self.assertRaisesRegex(RuntimeError, "stop before any effect"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker={}
                )
        self.assertEqual(["admission", "admission", "public-main"], events)
        self.assertEqual(2, candidate.call_count)
        fetch.assert_not_called()
        inflight.assert_not_called()
        rootbroker.assert_not_called()

    def test_target_imported_by_lock_winner_does_not_hide_ref_drift(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        initial = {
            "canonical_repository": str(deploy.CANONICAL_REPOSITORY),
            "current_head": "a" * 40,
            "current_branch": "main",
            "target_head": expected,
            "origin_main": "c" * 40,
            "clean": True,
            "shallow": False,
            "target_object_present": False,
        }
        drifted = {**initial, "origin_main": "d" * 40,
                   "target_object_present": True}
        with (
            patch.object(deploy, "_require_release_source_admission",
                         side_effect=deploy.DeploySchedulePreEffectRefusal(
                             "release admission blocked: source ancestry is unproved"
                         )) as admission,
            patch.object(deploy, "_canonical_main_refresh_candidate",
                         side_effect=[initial, drifted]),
            patch.object(deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
            patch.object(deploy, "_fresh_public_github_main") as public,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as rootbroker,
        ):
            with self.assertRaisesRegex(RuntimeError, "drift"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker={}
                )
        admission.assert_called_once_with(expected)
        fetch.assert_not_called()
        public.assert_not_called()
        rootbroker.assert_not_called()

    def test_missing_object_is_only_allowed_fetch_exception(self) -> None:
        deploy = real_deploy
        target = "b" * 40
        for message, snapshot, need_snapshot in (
            (
                "release admission blocked: source ancestry is unproved",
                {"target_object_present": True},
                True,
            ),
            ("release review admission missing: independent R3 required", None, False),
            ("release admission blocked: serving process identity mismatch", None, False),
        ):
            with (
                self.subTest(message=message),
                patch.object(
                    deploy, "_require_release_source_admission",
                    side_effect=deploy.DeploySchedulePreEffectRefusal(message),
                ),
                patch.object(
                    deploy, "_canonical_main_refresh_candidate",
                    return_value=snapshot,
                ) as candidate,
                patch.object(deploy, "_deploy_schedule_lock") as schedule_lock,
                patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
                patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
            ):
                with self.assertRaises(deploy.DeploySchedulePreEffectRefusal):
                    deploy._grabowski_runtime_deploy_schedule_impl(
                        target, local_mutation_tracker={}
                    )
            self.assertEqual(1 if need_snapshot else 0, candidate.call_count)
            schedule_lock.assert_not_called()
            fetch.assert_not_called()
            broker.assert_not_called()

    def test_object_import_acquisition_uses_budgeted_ttl_under_exact_scopes(self) -> None:
        deploy = real_deploy
        repo = Path("/fixture/canonical")
        keys = (
            "operation_key", "canonical_key", "common_dir_key",
            "objects_key", "origin_main_ref_key",
        )
        plan = {
            "canonical_repository": repo,
            "owner_id": "fixture:release-import",
            **{key: f"fixture:{key}" for key in keys},
        }
        resources = types.ModuleType("grabowski_resources")
        resources.operation_scope_contract = Mock(return_value={"scope": "locked"})
        resources.acquire_resources = Mock(return_value={"leases": []})
        resources.ResourceConflict = type("ResourceConflict", (RuntimeError,), {})
        with patch.dict(sys.modules, {"grabowski_resources": resources}):
            receipt = deploy._acquire_origin_main_refresh_resources(plan, "b" * 40)
        self.assertEqual({"leases": []}, receipt)
        resources.operation_scope_contract.assert_called_once()
        resources.acquire_resources.assert_called_once()
        args, kwargs = resources.acquire_resources.call_args
        self.assertEqual(plan["owner_id"], args[0])
        self.assertEqual([plan[k] for k in keys], args[1])
        self.assertEqual(
            deploy.ORIGIN_MAIN_REFRESH_LEASE_TTL_SECONDS,
            kwargs["ttl_seconds"],
        )
        self.assertEqual({"scope": "locked"}, kwargs["metadata"]["operation_scope"])

    def test_object_import_lease_ttl_covers_bounded_slow_git_reads(self) -> None:
        # Prior fixed five-minute leases could lapse while independent bounded
        # Git reads, public-main checks and the actual fetch were still active.
        # This includes a margin for the shared ref-refresh path and cleanup.
        deploy = real_deploy
        worst_case_read_budget = 14 * 30
        github_budget = 2 * deploy.PUBLIC_GITHUB_LOOKUP_TIMEOUT_SECONDS
        fetch_budget = 60
        coordination_and_finalization_budget = 300
        lower_bound = (
            worst_case_read_budget
            + github_budget
            + fetch_budget
            + coordination_and_finalization_budget
        )
        self.assertGreaterEqual(
            deploy.ORIGIN_MAIN_REFRESH_LEASE_TTL_SECONDS,
            lower_bound,
        )

    def test_exact_target_fetch_preserves_refs_and_oid_format(self) -> None:
        deploy = real_deploy
        repository = Path("/fixture/canonical")
        for object_format, width in (("sha1", 40), ("sha256", 64)):
            with self.subTest(object_format=object_format):
                expected = "b" * width
                snapshot = {
                    "canonical_repository": str(repository),
                    "current_head": "a" * width,
                    "current_branch": "main",
                    "target_head": expected,
                    "origin_main": "c" * width,
                    "clean": True,
                    "shallow": False,
                    "target_object_present": False,
                }
                keys = ["operation_key", "canonical_key", "common_dir_key",
                        "objects_key", "origin_main_ref_key"]
                plan = {
                    "canonical_repository": repository,
                    "owner_id": "fixture:object-import",
                    **{key: f"fixture:{key}" for key in keys},
                }
                leases = [{"resource_key": plan[key]} for key in keys]
                acquired = {"leases": leases}
                after = {**snapshot, "target_object_present": True}
                state = {"calls": []}

                def git_read(repo: Path, *args: str) -> dict:
                    self.assertEqual(repository, repo)
                    if args == ("rev-parse", "--show-object-format"):
                        return self._git_success(object_format)
                    if args == ("rev-parse", "--verify", f"{expected}^{{commit}}"):
                        return self._git_success(expected)
                    self.fail(f"unexpected object fetch read: {args}")

                with (
                    patch.object(deploy, "_origin_main_refresh_plan", return_value=plan),
                    patch.object(
                        deploy, "_acquire_origin_main_refresh_resources",
                        return_value=acquired,
                    ),
                    patch.object(
                        deploy, "_lease_for_key",
                        side_effect=lambda _acq, key: {"resource_key": key},
                    ),
                    patch.object(deploy, "_require_origin_main_refresh_checkout_certainty"),
                    patch.object(
                        deploy, "_canonical_main_refresh_candidate",
                        side_effect=[snapshot, after],
                    ),
                    patch.object(deploy, "_git_result", side_effect=git_read),
                    patch.object(
                        deploy, "_fresh_public_github_main", return_value=expected,
                    ) as remote,
                    patch.object(deploy, "_append_deploy_audit") as audit,
                    patch.object(
                        deploy, "_mutating_git_result",
                        return_value=self._git_success(""),
                    ) as git_mutate,
                    patch.object(
                        deploy, "_release_origin_main_refresh_resources",
                        return_value={"released": list(leases)},
                    ) as release,
                ):
                    deploy._fetch_exact_release_admission_target(
                        expected, snapshot, local_mutation_tracker=state
                    )
                self.assertEqual(2, remote.call_count)
                self.assertEqual(2, audit.call_count)
                self.assertEqual("fetch", git_mutate.call_args.args[1])
                self.assertIn("--no-write-fetch-head", git_mutate.call_args.args)
                self.assertNotIn("update-ref", git_mutate.call_args.args)
                release.assert_called_once()
                self.assertEqual(
                    expected, state["admission_target_fetch"]["expected_head"]
                )
                self.assertEqual(
                    "grabowski_runtime_deploy_origin_main_fetch_effect",
                    state["admission_target_fetch"]["kind"],
                )


    def test_ref_drift_after_successful_fetch_is_not_admission(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        repo = Path("/fixture/canonical")
        initial = {
            "canonical_repository": str(repo), "current_head": "a" * 40,
            "current_branch": "main", "target_head": expected,
            "origin_main": "c" * 40, "clean": True, "shallow": False,
            "target_object_present": False,
        }
        drifted = {
            **initial, "target_object_present": True,
            "origin_main": "d" * 40,
        }
        names = ("operation_key", "canonical_key", "common_dir_key",
                 "objects_key", "origin_main_ref_key")
        plan = {"canonical_repository": repo, "owner_id": "fixture:import",
                **{name: name for name in names}}
        leases = [{"resource_key": name} for name in names]
        tracker: dict = {}

        def read(repo_arg: Path, *args: str) -> dict:
            self.assertEqual(repo, repo_arg)
            if args == ("rev-parse", "--show-object-format"):
                return self._git_success("sha1")
            if args == ("rev-parse", "--verify", f"{expected}^{{commit}}"):
                return self._git_success(expected)
            self.fail("unrecognized Git object read")

        with (
            patch.object(deploy, "_origin_main_refresh_plan", return_value=plan),
            patch.object(deploy, "_acquire_origin_main_refresh_resources",
                         return_value={"leases": leases}),
            patch.object(deploy, "_lease_for_key",
                         side_effect=lambda _acq, key: {"resource_key": key}),
            patch.object(deploy, "_require_origin_main_refresh_checkout_certainty"),
            patch.object(deploy, "_canonical_main_refresh_candidate",
                         side_effect=[initial, drifted]),
            patch.object(deploy, "_git_result", side_effect=read),
            patch.object(deploy, "_fresh_public_github_main",
                         return_value=expected),
            patch.object(deploy, "_append_deploy_audit") as audit,
            patch.object(deploy, "_mutating_git_result",
                         return_value=self._git_success("")),
            patch.object(deploy, "_release_origin_main_refresh_resources",
                         return_value={"released": leases}) as release,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
        ):
            with self.assertRaisesRegex(RuntimeError, "altered canonical checkout"):
                deploy._fetch_exact_release_admission_target(
                    expected, initial, local_mutation_tracker=tracker,
                )
        self.assertEqual(
            "grabowski_runtime_deploy_origin_main_fetch_effect",
            tracker["admission_target_fetch"]["kind"],
        )
        self.assertEqual(1, audit.call_count)
        release.assert_called_once()
        broker.assert_not_called()

    def test_review_denial_after_fetch_blocks_before_root_or_index(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        calls: list[str] = []

        def admission(head: str) -> dict:
            self.assertEqual(expected, head)
            calls.append("admission")
            if len(calls) == 1:
                raise deploy.DeploySchedulePreEffectRefusal(
                    "release admission blocked: source ancestry is unproved"
                )
            raise deploy.DeploySchedulePreEffectRefusal(
                "release review admission missing: independent R3 required"
            )

        def fetch(head: str, snapshot: dict, *, local_mutation_tracker: dict) -> None:
            calls.append("fetch")
            local_mutation_tracker["admission_target_fetch"] = {
                "kind": "mocked-object-effect-not-a-review-pass"
            }

        with (
            patch.object(deploy, "_require_release_source_admission", side_effect=admission),
            patch.object(deploy, "_canonical_main_refresh_candidate",
                         return_value={"target_object_present": False}),
            patch.object(deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(deploy, "_fetch_exact_release_admission_target", side_effect=fetch),
            patch.object(deploy, "_fresh_public_github_main") as remote,
            patch.object(deploy, "inflight_runtime_job_evidence") as index,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
        ):
            with self.assertRaisesRegex(RuntimeError, "independent R3"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker={}
                )
        self.assertEqual(["admission", "fetch", "admission"], calls)
        remote.assert_not_called()
        index.assert_not_called()
        broker.assert_not_called()

    def test_wrong_oid_width_blocks_before_fetch(self) -> None:
        deploy = real_deploy
        expected = "b" * 63
        initial = {"target_head": expected, "target_object_present": False}
        with patch.object(deploy, "_origin_main_refresh_plan") as plan:
            with self.assertRaisesRegex(RuntimeError, "exact missing target"):
                deploy._fetch_exact_release_admission_target(
                    expected, initial, local_mutation_tracker={}
                )
        plan.assert_not_called()



    def test_pre_effect_git_refusal_does_not_forge_fetch_uncertainty(self) -> None:
        """No-process preflight denial must not become evidence of a Git effect."""
        deploy = real_deploy
        expected = "b" * 40
        repo = Path("/fixture/canonical")
        snapshot = {
            "canonical_repository": str(repo),
            "current_head": "a" * 40,
            "current_branch": "main",
            "target_head": expected,
            "origin_main": "c" * 40,
            "clean": True,
            "shallow": False,
            "target_object_present": False,
        }
        names = ("operation_key", "canonical_key", "common_dir_key",
                 "objects_key", "origin_main_ref_key")
        plan = {"canonical_repository": repo, "owner_id": "fixture:preflight",
                **{name: name for name in names}}
        leases = [{"resource_key": name} for name in names]
        for error, effect_may_have_started in (
            (deploy.DeploySchedulePreEffectRefusal("operator preflight denied"), False),
            (RuntimeError("unknown git dispatch failure"), True),
        ):
            tracker: dict = {}
            with (
                self.subTest(error=type(error).__name__),
                patch.object(deploy, "_origin_main_refresh_plan", return_value=plan),
                patch.object(deploy, "_acquire_origin_main_refresh_resources",
                             return_value={"leases": leases}),
                patch.object(deploy, "_lease_for_key",
                             side_effect=lambda _acq, key: {"resource_key": key}),
                patch.object(deploy, "_require_origin_main_refresh_checkout_certainty"),
                patch.object(deploy, "_canonical_main_refresh_candidate",
                             return_value=snapshot),
                patch.object(deploy, "_git_result",
                             return_value=self._git_success("sha1")),
                patch.object(deploy, "_fresh_public_github_main",
                             return_value=expected),
                patch.object(deploy, "_append_deploy_audit") as audit,
                patch.object(deploy, "_mutating_git_result",
                             side_effect=error) as git_mutate,
                patch.object(deploy, "_release_origin_main_refresh_resources",
                             return_value={"released": leases}) as release,
                patch.object(deploy.privileged, "ensure_rootbroker_authority") as rootbroker,
            ):
                with self.assertRaisesRegex(type(error), str(error)):
                    deploy._fetch_exact_release_admission_target(
                        expected, snapshot, local_mutation_tracker=tracker,
                    )
            self.assertEqual(
                "admission_target_fetch" in tracker, effect_may_have_started
            )
            if effect_may_have_started:
                self.assertEqual(
                    "outcome_unknown", tracker["admission_target_fetch"]["status"]
                )
            git_mutate.assert_called_once()
            audit.assert_called_once()
            release.assert_called_once()
            rootbroker.assert_not_called()

    def test_object_fetch_failure_is_ambiguity_not_release_success(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        repo = Path("/fixture/canonical")
        initial = {
            "canonical_repository": str(repo), "current_head": "a" * 40,
            "current_branch": "main", "target_head": expected,
            "origin_main": "c" * 40, "clean": True, "shallow": False,
            "target_object_present": False,
        }
        names = ("operation_key", "canonical_key", "common_dir_key",
                 "objects_key", "origin_main_ref_key")
        plan = {"canonical_repository": repo, "owner_id": "fixture:import",
                **{name: name for name in names}}
        snapshots = [{"resource_key": name} for name in names]
        result = self._git_success("")
        result["returncode"] = 1
        result["timed_out"] = True
        tracker: dict = {}
        with (
            patch.object(deploy, "_origin_main_refresh_plan", return_value=plan),
            patch.object(deploy, "_acquire_origin_main_refresh_resources",
                         return_value={"leases": snapshots}),
            patch.object(deploy, "_lease_for_key",
                         side_effect=lambda _acq, key: {"resource_key": key}),
            patch.object(deploy, "_require_origin_main_refresh_checkout_certainty"),
            patch.object(deploy, "_canonical_main_refresh_candidate",
                         return_value=initial),
            patch.object(deploy, "_git_result",
                         return_value=self._git_success("sha1")),
            patch.object(deploy, "_fresh_public_github_main",
                         return_value=expected),
            patch.object(deploy, "_append_deploy_audit"),
            patch.object(deploy, "_mutating_git_result",
                         return_value=result),
            patch.object(deploy, "_release_origin_main_refresh_resources",
                         return_value={"released": snapshots}) as release,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
        ):
            with self.assertRaisesRegex(RuntimeError, "object fetch failed"):
                deploy._fetch_exact_release_admission_target(
                    expected, initial, local_mutation_tracker=tracker,
                )
        self.assertEqual(
            "outcome_unknown", tracker["admission_target_fetch"]["status"]
        )
        self.assertTrue(tracker["admission_target_fetch"]["effect_may_have_started"])
        release.assert_called_once()
        broker.assert_not_called()


    def test_captain_combined_object_import_then_ref_refresh_is_not_lost(self) -> None:
        """Two real source effects must remain separately authenticated and ordered."""
        head = "b" * 40
        canonical = "/home/alex/repos/grabowski"
        resources = {
            "canonical_repository": canonical,
            "expected_head": head,
            "previous_head": "a" * 40,
            "previous_branch": "main",
            "previous_origin_main": "c" * 40,
            "owner_id": "runtime-deploy-ref:test",
            "operation_resource_key": f"repo:{canonical}:operation:runtime-deploy-origin-main-refresh",
            "canonical_resource_key": f"path:{canonical}",
            "common_dir_resource_key": f"path:{canonical}/.git",
            "objects_resource_key": f"path:{canonical}/.git/objects",
            "origin_main_ref_resource_key": f"path:{canonical}/.git/refs/remotes/origin/main",
        }

        def signed(material: dict, *, digest: str = "evidence_sha256") -> dict:
            return {**material, digest: grips.sha256_json(material)}

        imported = signed({
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_origin_main_fetch_effect",
            **resources,
            "target_object": {"before_fetch_present": False, "after_fetch_commit": head},
            "fetch": {"returncode": 0, "timed_out": False},
            "public_github_main": {"before_fetch": head},
            "effect_observed": True,
        })
        refreshed = signed({
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_origin_main_refresh_effect",
            **resources,
            "observed_origin_main": head,
            "fetch": {"returncode": 0, "timed_out": False},
            "update_ref": {
                "returncode": 0, "timed_out": False, "reported_success": True
            },
            "public_github_main": {"before_fetch": head, "after_fetch": head},
            "effect_observed": True,
        })
        legacy_refresh = dict(refreshed)
        legacy_refresh["kind"] = "grabowski_runtime_deploy_origin_main_refresh"
        legacy_refresh["public_github_main"] = {
            "before_fetch": head, "after_fetch": head, "after_cas": head
        }
        legacy_refresh.pop("effect_observed")
        legacy_refresh.pop("evidence_sha256")
        legacy_refresh = signed(legacy_refresh, digest="receipt_sha256")

        def valid(effects: list[dict]) -> bool:
            bundle = signed({
                "schema_version": 1,
                "kind": "grabowski_runtime_deploy_local_mutation_bundle",
                "effects": effects,
            })
            return grips._runtime_deploy_local_mutation_evidence_valid(
                bundle, expected_job_prefix="grabowski-job-", expected_head=head
            )

        self.assertTrue(grips._runtime_deploy_origin_main_fetch_effect_evidence_valid(
            imported, expected_head=head
        ))
        self.assertTrue(grips._runtime_deploy_origin_main_refresh_effect_evidence_valid(
            refreshed, expected_head=head
        ))
        self.assertTrue(grips._runtime_deploy_origin_main_refresh_evidence_valid(
            legacy_refresh, expected_head=head
        ))
        self.assertTrue(valid([imported, refreshed]))
        self.assertTrue(valid([imported, legacy_refresh]))
        self.assertFalse(valid([refreshed, imported]))
        self.assertFalse(valid([imported, imported]))
        self.assertFalse(valid([imported, refreshed, legacy_refresh]))
        self.assertFalse(valid([imported, {**refreshed, "evidence_sha256": "0" * 64}]))
        self.assertFalse(grips._runtime_deploy_local_mutation_evidence_valid(
            signed({
                "schema_version": 1,
                "kind": "grabowski_runtime_deploy_local_mutation_bundle",
                "effects": [imported, refreshed],
            }),
            expected_job_prefix="grabowski-job-",
            expected_head="d" * 40,
        ))

    def test_captain_runtime_deploy_marks_review_gate_blocked(self) -> None:
        # Exercise the Captain policy seam without import-order effects from
        # the old scheduler fixture's synthetic modules.
        fake_deploy = types.ModuleType("grabowski_self_deploy")
        admission = Mock(side_effect=RuntimeError("release admission missing"))
        fake_deploy._require_release_source_admission = admission
        with patch.dict(sys.modules, {"grabowski_self_deploy": fake_deploy}):
            gate = grips._captain_independent_review_gate(
                {"expected_head": "b" * 40},
                [
                    {
                        "action": "runtime-deploy",
                        "target": {
                            "repo": "heimgewebe/grabowski",
                            "runtime_target": "heim-pc",
                            "adapter": "grabowski-self",
                        },
                    }
                ],
            )
        self.assertEqual("blocked", gate["status"])
        self.assertIn("release", str(gate.get("details", gate.get("reason", ""))))
        admission.assert_called_once_with("b" * 40)



    def test_captain_missing_exact_public_target_defers_only_object_import(self) -> None:
        """A Captain preview may only probe the exact OID via safe Git plumbing."""
        deploy = real_deploy
        expected = "b" * 40
        absent = self._git_success("")
        absent["returncode"] = 1
        denial = deploy.DeploySchedulePreEffectRefusal(
            "release admission blocked: source ancestry is unproved"
        )
        with (
            patch.object(deploy, "_require_release_source_admission", side_effect=denial) as admit,
            patch.object(deploy, "_git_result", return_value=absent) as git_read,
            patch.object(deploy, "_canonical_main_refresh_candidate") as porcelain,
            patch.object(deploy, "_fresh_public_github_main", return_value=expected) as public,
            patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as rootbroker,
        ):
            gate = grips._captain_independent_review_gate(
                {"expected_head": expected}, [{"action": "runtime-deploy"}],
            )
        self.assertEqual("pass", gate["status"])
        self.assertIsNone(gate["details"]["required"])
        self.assertIs(gate["details"]["protected_import_pending"], True)
        self.assertIs(gate["details"]["release_authorized"], False)
        self.assertIs(gate["details"]["full_readmission_required"], True)
        admit.assert_called_once_with(expected)
        git_read.assert_called_once_with(
            deploy.CANONICAL_REPOSITORY,
            "rev-parse", "--verify", "--quiet", f"{expected}^{{commit}}",
        )
        porcelain.assert_not_called()
        public.assert_called_once_with(expected)
        fetch.assert_not_called()
        rootbroker.assert_not_called()

    def test_captain_missing_target_requires_exact_plumbing_and_public_main(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        denied = deploy.DeploySchedulePreEffectRefusal(
            "release admission blocked: source ancestry is unproved"
        )
        good = self._git_success("")
        good["returncode"] = 1
        cases = []
        for key, value in (
            ("returncode", 0), ("returncode", 2),
            ("returncode", False), ("timed_out", True),
            ("stdout", "spoof"), ("stderr", "object is unavailable"),
            ("stdout_truncated", True), ("stderr_truncated", True),
        ):
            altered = dict(good)
            altered[key] = value
            cases.append((key, altered, expected))
        cases.append(("public-main-drift", good, "c" * 40))
        for label, result, remote in cases:
            with (
                self.subTest(case=label),
                patch.object(deploy, "_require_release_source_admission", side_effect=denied),
                patch.object(deploy, "_git_result", return_value=result),
                patch.object(deploy, "_canonical_main_refresh_candidate") as porcelain,
                patch.object(deploy, "_fresh_public_github_main", return_value=remote),
                patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
            ):
                gate = grips._captain_independent_review_gate(
                    {"expected_head": expected}, [{"action": "runtime-deploy"}],
                )
            self.assertEqual("blocked", gate["status"])
            porcelain.assert_not_called()
            fetch.assert_not_called()

    def test_source_diff_without_explicit_transport_completeness_blocks(self) -> None:
        deploy = real_deploy
        observed = self._git_success("docs/guide.md\x00")
        del observed["stdout_truncated"]
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(deploy, "_git_result", side_effect=[self._git_success(""), observed]),
        ):
            with self.assertRaisesRegex(RuntimeError, "complete source diff"):
                deploy._require_release_source_admission("b" * 40)

    def test_source_ancestor_missing_explicit_zero_exit_blocks(self) -> None:
        deploy = real_deploy
        ancestor = self._git_success("")
        ancestor["returncode"] = False
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(deploy, "_git_result", side_effect=[ancestor]) as read,
        ):
            with self.assertRaisesRegex(RuntimeError, "source ancestry"):
                deploy._require_release_source_admission("b" * 40)
        read.assert_called_once()

    def test_source_path_escape_from_docs_prefix_blocks(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("docs/../src/grabowski_agent_role.py\x00"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "source paths"):
                deploy._require_release_source_admission("b" * 40)

    def test_truncated_and_unterminated_path_output_blocks(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("docs/readme.md"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "source path boundary"):
                deploy._require_release_source_admission("b" * 40)


    def test_redacted_documentation_path_cannot_grant_release_admission(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("docs/<REDACTED>\x00"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "source paths"):
                deploy._require_release_source_admission("b" * 40)

    def test_executable_script_inside_docs_does_not_get_documentation_exemption(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("docs/run_deploy.sh\x00"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "release review admission missing"):
                deploy._require_release_source_admission("b" * 40)



if __name__ == "__main__":
    unittest.main()