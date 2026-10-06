from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

from tests.test_grips import CAPTAIN_HEAD, grips
from tests.test_self_deploy import SELF_DEPLOY, _result, _source_identity


class Pr1366CurrentHeadReviewRegressions(unittest.TestCase):
    def _promotion_evidence(self) -> dict:
        material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_pending_unit_promotion",
            "unit": "grabowski-job-123456abcdef",
            "deploy_index_updated": True,
            "index_updated_at_unix": 1,
        }
        return {**material, "evidence_sha256": grips.sha256_json(material)}

    def test_captain_accepts_promotion_and_rejects_tampered_evidence(self) -> None:
        promotion = self._promotion_evidence()
        kwargs = {"expected_job_prefix": "grabowski-job-", "expected_head": CAPTAIN_HEAD}
        self.assertTrue(grips._runtime_deploy_local_mutation_evidence_valid(promotion, **kwargs))
        for changes in (
            {"schema_version": True},
            {"unit": "foreign-job-123456abcdef"},
            {"deploy_index_updated": False},
            {"index_updated_at_unix": True},
            {"index_updated_at_unix": -1},
            {"extra": "unexpected"},
        ):
            with self.subTest(changes=changes):
                material = {key: value for key, value in promotion.items() if key != "evidence_sha256"}
                material.update(changes)
                forged = {**material, "evidence_sha256": grips.sha256_json(material)}
                self.assertFalse(grips._runtime_deploy_local_mutation_evidence_valid(forged, **kwargs))
        tampered = {**promotion, "unit": "grabowski-job-fedcba654321"}
        self.assertFalse(grips._runtime_deploy_local_mutation_evidence_valid(tampered, **kwargs))

    def test_materialization_lease_guard_rejects_missing_or_changed_snapshot(self) -> None:
        owner = "runtime-deploy-source:bbbbbbbbbbbb:abc123def456"
        first = {
            "resource_key": "path:/tmp/one",
            "owner_id": owner,
            "acquired_at_unix": 10,
            "updated_at_unix": 10,
            "expires_at_unix": 100,
            "metadata_sha256": "1" * 64,
        }
        second = {
            "resource_key": "path:/tmp/two",
            "owner_id": owner,
            "acquired_at_unix": 10,
            "updated_at_unix": 10,
            "expires_at_unix": 100,
            "metadata_sha256": "2" * 64,
        }
        resources = types.ModuleType("grabowski_resources")
        resources.inspect_resources = Mock(
            return_value={
                first["resource_key"]: dict(first),
                second["resource_key"]: dict(second),
            }
        )
        with patch.dict(sys.modules, {"grabowski_resources": resources}, clear=False):
            SELF_DEPLOY._require_auto_deploy_source_mutation_leases(
                owner, [first, second]
            )
            changed = dict(second)
            changed["updated_at_unix"] = 11
            resources.inspect_resources.return_value = {
                first["resource_key"]: dict(first),
                second["resource_key"]: changed,
            }
            with self.assertRaises(SELF_DEPLOY.DeploySchedulePreEffectRefusal):
                SELF_DEPLOY._require_auto_deploy_source_mutation_leases(
                    owner, [first, second]
                )
            resources.inspect_resources.return_value = {
                first["resource_key"]: dict(first)
            }
            with self.assertRaises(SELF_DEPLOY.DeploySchedulePreEffectRefusal):
                SELF_DEPLOY._require_auto_deploy_source_mutation_leases(
                    owner, [first, second]
                )

    def test_materialization_audit_failure_reports_observed_auto_source_effect(self) -> None:
        local_mutation_tracker: dict[str, object] = {}
        expected = "b" * 40
        canonical = Path("/tmp/pr1366-review-canonical")
        target = Path("/tmp/pr1366-review-auto-source")
        owner = "runtime-deploy-source:bbbbbbbbbbbb:abc123def456"
        generation = "abc123def456"
        operation_key = f"repo:{canonical}:operation:worktree-add:auto"
        path_key = f"path:{target}"
        common_dir_key = f"path:{canonical / '.git'}"
        checkout_key = "a" * 64
        plan = {
            "canonical_repository": canonical,
            "target": target,
            "owner_id": owner,
            "generation": generation,
            "obligation_id": "goo-runtime-deploy-source-bbbbbbbbbbbb-abc123def456",
            "operation_key": operation_key,
            "path_key": path_key,
        }
        leases = [
            {
                "resource_key": operation_key,
                "owner_id": owner,
                "acquired_at_unix": 10,
                "updated_at_unix": 10,
                "expires_at_unix": 100,
                "metadata_sha256": "1" * 64,
            },
            {
                "resource_key": path_key,
                "owner_id": owner,
                "acquired_at_unix": 10,
                "updated_at_unix": 10,
                "expires_at_unix": 100,
                "metadata_sha256": "2" * 64,
            },
            {
                "resource_key": common_dir_key,
                "owner_id": owner,
                "acquired_at_unix": 10,
                "updated_at_unix": 10,
                "expires_at_unix": 100,
                "metadata_sha256": "3" * 64,
            },
        ]
        fence_evidence = {
            "repo": str(canonical),
            "git_common_dir": str(canonical / ".git"),
            "checkout_path": str(target),
            "checkout_key": checkout_key,
            "owner_id": owner,
            "expected_head": expected,
            "expected_branch": None,
            "obligation_id": plan["obligation_id"],
        }
        fence = {
            "fence_id": "f" * 32,
            "checkout_key": checkout_key,
            "owner_id": owner,
            "lease_owner_id": owner,
            "operation": "materialize",
            "operation_id": generation,
            "resource_keys": sorted([path_key, common_dir_key]),
            "evidence": fence_evidence,
            "evidence_sha256": "4" * 64,
            "created_at_unix": 10,
            "cleared_at_unix": None,
            "clearance": None,
            "clearance_sha256": None,
        }
        lifecycle = {
            "checkout_key": checkout_key,
            "owner_id": owner,
            "retention_until_unix": 100,
            "created_at_unix": 10,
            "updated_at_unix": 10,
        }
        retention = {
            "checkout_key": checkout_key,
            "owner_id": owner,
            "retention_until_unix": 100,
            "expected_head": expected,
            "expected_branch": None,
        }
        stale = {
            "canonical_repository": str(canonical),
            "current_head": "a" * 40,
            "target_head": expected,
            "origin_main": expected,
            "clean": True,
            "lease_evidence": {"resource_key": f"path:{canonical}", "lease": None},
        }
        identity = _source_identity(
            target,
            expected,
            kind="detached-worktree",
            canonical=canonical,
        )
        with patch.object(
            SELF_DEPLOY, "_canonical_stale_main_snapshot", side_effect=[stale, stale]
        ), patch.object(
            SELF_DEPLOY, "_auto_deploy_source_plan", return_value=plan
        ), patch.object(
            SELF_DEPLOY,
            "_acquire_auto_deploy_source_resources",
            return_value={
                "leases": leases,
                "common_dir_key": common_dir_key,
                "checkout_uncertainty_fence": fence,
            },
        ), patch.object(
            SELF_DEPLOY,
            "_open_auto_deploy_source_obligation",
            return_value={"state": "open", "obligation_id": plan["obligation_id"]},
        ), patch.object(
            SELF_DEPLOY, "_reserve_auto_deploy_source_lifecycle", return_value=lifecycle
        ), patch.object(
            SELF_DEPLOY.os.path, "lexists", side_effect=[False, False, True]
        ), patch.object(
            SELF_DEPLOY, "_worktree_registration_present", return_value=True
        ), patch.object(
            SELF_DEPLOY, "_mutating_git_result", return_value=_result("")
        ), patch.object(
            SELF_DEPLOY,
            "_require_auto_deploy_source_mutation_leases",
            return_value=None,
            create=True,
        ), patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            return_value=(target, target / SELF_DEPLOY.RUNNER_RELATIVE_PATH, identity),
        ), patch.object(
            SELF_DEPLOY, "_bind_auto_deploy_source_retention", return_value=retention
        ), patch.object(
            SELF_DEPLOY,
            "_release_auto_deploy_source_resources",
            return_value={"released": [leases[0], leases[2]]},
        ), patch.object(
            SELF_DEPLOY,
            "_close_auto_deploy_source_obligation",
            return_value={
                "state": "completed",
                "obligation_id": plan["obligation_id"],
                "close_file_sha256": "c" * 64,
            },
        ), patch.object(
            SELF_DEPLOY, "_append_deploy_audit", side_effect=OSError("audit unavailable")
        ), patch.object(
            SELF_DEPLOY, "_clear_auto_deploy_source_uncertainty"
        ) as clear_uncertainty:
            with self.assertRaises(
                SELF_DEPLOY.DeployScheduleFailureAfterLocalMutation
            ) as raised:
                SELF_DEPLOY._materialize_auto_deploy_source(
                    expected,
                    local_mutation_tracker=local_mutation_tracker,
                )
        clear_uncertainty.assert_not_called()
        evidence = raised.exception.local_mutation_evidence
        self.assertEqual(local_mutation_tracker["auto_source_materialization"], evidence)
        self.assertEqual(
            evidence["kind"], "grabowski_runtime_deploy_auto_source_effect"
        )
        self.assertTrue(evidence["effect_observed"])
        self.assertEqual(evidence["expected_head"], expected)
        self.assertEqual(evidence["uncertainty_fence_id"], fence["fence_id"])
        self.assertEqual(
            evidence["source_identity_sha256"], identity["identity_sha256"]
        )

    def test_scheduler_preserves_rootbroker_effect_when_audit_fails(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        expected = "d" * 40
        identity = _source_identity(repo, expected)
        authority = {
            "success": True,
            "outcome": "succeeded",
            "expected_head": expected,
            "attested_head": expected,
            "effect_started": True,
            "request_id": "rootbroker-audit-failure",
            "reference_sha256": "a" * 64,
        }
        failure = RuntimeError("operator audit unavailable")
        failure.authority_result = authority
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            return_value=(repo, runner, identity),
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(
            SELF_DEPLOY, "_fresh_public_github_main", return_value=expected
        ), patch.object(
            SELF_DEPLOY,
            "inflight_runtime_job_evidence",
            return_value={"error": None, "inflight_units": []},
        ), patch.object(
            SELF_DEPLOY.privileged,
            "ensure_rootbroker_authority",
            side_effect=failure,
        ):
            with self.assertRaises(
                SELF_DEPLOY.DeployScheduleFailureAfterLocalMutation
            ) as raised:
                SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 8)
        evidence = raised.exception.local_mutation_evidence
        self.assertEqual(
            evidence["kind"],
            "grabowski_runtime_deploy_rootbroker_authority_effect",
        )
        self.assertEqual(evidence["expected_head"], expected)
        self.assertEqual(evidence["request_id"], authority["request_id"])
        self.assertTrue(evidence["effect_started"])

    def test_rootbroker_effect_evidence_requires_confirmed_target_head(self) -> None:
        expected = "d" * 40
        base = {
            "success": False,
            "outcome": "failed",
            "expected_head": expected,
            "attested_head": "a" * 40,
            "effect_started": True,
            "request_id": "rootbroker-noeffect",
            "reference_sha256": "b" * 64,
        }
        self.assertIsNone(
            SELF_DEPLOY._rootbroker_authority_effect_evidence(base, expected)
        )
        self.assertIsNone(
            SELF_DEPLOY._rootbroker_authority_effect_evidence(
                {**base, "success": True},
                expected,
            )
        )
        self.assertIsNone(
            SELF_DEPLOY._rootbroker_authority_effect_evidence(
                {
                    **base,
                    "success": True,
                    "expected_head": "c" * 40,
                    "attested_head": expected,
                },
                expected,
            )
        )
        confirmed = {
            **base,
            "success": True,
            "outcome": "succeeded",
            "expected_head": expected,
            "attested_head": expected,
        }
        evidence = SELF_DEPLOY._rootbroker_authority_effect_evidence(
            confirmed, expected
        )
        self.assertIsInstance(evidence, dict)
        assert isinstance(evidence, dict)
        self.assertEqual(evidence["expected_head"], expected)
        self.assertEqual(evidence["attested_head"], expected)

    def test_scheduler_preserves_successful_materialization_effect_on_later_failure(
        self,
    ) -> None:
        canonical = Path(__file__).resolve().parents[1]
        target = Path("/tmp/pr1366-auto-source-later-failure")
        runner = target / SELF_DEPLOY.RUNNER_RELATIVE_PATH
        expected = "d" * 40
        generation = "abc123def456"
        owner = f"runtime-deploy-source:{expected[:12]}:{generation}"
        identity = _source_identity(
            target,
            expected,
            kind="detached-worktree",
            canonical=canonical,
        )
        auto_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_auto_source_effect",
            "expected_head": expected,
            "repository": str(target),
            "owner_id": owner,
            "generation": generation,
            "path_resource_key": f"path:{target}",
            "source_identity_sha256": identity["identity_sha256"],
            "lifecycle_checkout_key": "e" * 64,
            "uncertainty_fence_id": "f" * 32,
            "uncertainty_evidence_sha256": "1" * 64,
            "effect_observed": True,
        }
        auto = {
            **auto_material,
            "evidence_sha256": SELF_DEPLOY._source_identity_sha256(auto_material),
        }
        materialization = {
            "schema_version": 1,
            "kind": "grabowski_auto_runtime_deploy_source",
            "owner_id": owner,
            "repository": str(target),
            "expected_head": expected,
        }
        stale = {
            "canonical_repository": str(canonical),
            "current_head": expected,
            "current_branch": "feature/active",
            "target_head": expected,
            "origin_main": expected,
            "clean": True,
            "lease_evidence": {
                "resource_key": f"path:{canonical}",
                "lease": None,
            },
        }
        canonical_calls = 0

        def source_preflight(*_args, **_kwargs):
            nonlocal canonical_calls
            canonical_calls += 1
            if canonical_calls <= 2:
                raise RuntimeError("canonical feature checkout")
            raise RuntimeError("post-materialization source readback failed")

        def materialize(_expected, *, local_mutation_tracker):
            self.assertEqual(_expected, expected)
            local_mutation_tracker["auto_source_materialization"] = dict(auto)
            return target, runner, identity, materialization

        authority = {
            "success": True,
            "outcome": "already_current",
            "expected_head": expected,
            "attested_head": expected,
            "effect_started": False,
        }
        with patch.object(
            SELF_DEPLOY, "CANONICAL_REPOSITORY", canonical
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(
            SELF_DEPLOY, "_fresh_public_github_main", return_value=expected
        ), patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            side_effect=source_preflight,
        ), patch.object(
            SELF_DEPLOY, "_canonical_stale_main_snapshot", return_value=stale
        ), patch.object(
            SELF_DEPLOY,
            "inflight_runtime_job_evidence",
            return_value={"error": None, "inflight_units": []},
        ), patch.object(
            SELF_DEPLOY.privileged,
            "ensure_rootbroker_authority",
            return_value=authority,
        ), patch.object(
            SELF_DEPLOY, "_require_target_deploy_runner"
        ), patch.object(
            SELF_DEPLOY,
            "_materialize_auto_deploy_source",
            side_effect=materialize,
        ), patch.object(
            SELF_DEPLOY, "_cleanup_auto_deploy_source_before_dispatch"
        ):
            with self.assertRaises(
                SELF_DEPLOY.DeployScheduleFailureAfterLocalMutation
            ) as raised:
                SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 8)
        self.assertEqual(
            raised.exception.local_mutation_evidence["kind"],
            "grabowski_runtime_deploy_auto_source_effect",
        )
        self.assertEqual(
            raised.exception.local_mutation_evidence["evidence_sha256"],
            auto["evidence_sha256"],
        )

    def test_captain_preserves_returned_local_effect_on_post_return_failures(
        self,
    ) -> None:
        from tests.test_grips import captain_action

        action = captain_action(
            action="runtime-deploy",
            target={
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
                "adapter": "grabowski-self",
            },
            risk={
                "risk_level": "high",
                "irreversibility": "reversible",
                "recovery_path": "read back scheduling state",
            },
            receipt_path="receipts/captain/runtime-deploy.json",
        )
        preflight = {
            "adapter": "grabowski-self",
            "repository": "/home/alex/repos/grabowski",
            "runner": "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
            "job_root": str(Path.home() / ".local/state/grabowski/jobs"),
            "job_prefix": "grabowski-job-",
            "expected_head": CAPTAIN_HEAD,
            "source_kind": "canonical-main",
            "source_identity_sha256": "e" * 64,
            "target": {"service": "grabowski-mcp", "runtime_target": "heim-pc"},
            "ready": True,
        }
        reconciliation_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_stale_pending_reconciliation",
            "unit": "grabowski-job-123456abcdef",
            "dispatch_outcome": "not_started",
            "deploy_index_updated": True,
            "audit_recorded": True,
            "index_updated_at_unix": 1,
        }
        reconciliation = {
            **reconciliation_material,
            "evidence_sha256": grips.sha256_json(reconciliation_material),
        }
        unit = "grabowski-job-abcdef012345"
        job_dir = Path(preflight["job_root"]) / unit
        schedule = {
            "scheduled": True,
            "already_scheduled": False,
            "expected_head": CAPTAIN_HEAD,
            "requested_delay_seconds": 8,
            "delay_seconds": 8,
            "unit": unit,
            "argv_sha256": "d" * 64,
            "source_identity_sha256": "e" * 64,
            "source_identity": {"identity_sha256": "e" * 64},
            "metadata_path": str(job_dir / "metadata.json"),
            "stdout_path": str(job_dir / "stdout.log"),
            "stderr_path": str(job_dir / "stderr.log"),
            "expected_connector_disconnect": True,
            "status_tool": "grabowski_job_status",
            "logs_tool": "grabowski_job_logs",
            "local_mutation_evidence": reconciliation,
        }

        with self.subTest(failure="source-readback"), patch.object(
            grips, "_runtime_deploy_self_preflight", return_value=preflight
        ), patch.object(
            grips, "_runtime_deploy_self_schedule", return_value=schedule
        ), patch.object(
            grips,
            "_runtime_deploy_self_schedule_source_preflight",
            side_effect=RuntimeError("source readback failed"),
        ):
            execution = grips._run_captain_runtime_deploy(
                action,
                {"expected_head": CAPTAIN_HEAD, "delay_seconds": 8},
            )
            self.assertTrue(execution["command_returned"])
            self.assertTrue(execution["mutation_outcome_unknown"])
            self.assertTrue(execution["local_mutation_outcome_unknown"])
            self.assertTrue(execution["local_mutation_observed"])
            self.assertEqual(execution["local_mutation_evidence"], reconciliation)

        invalid_schedule = {
            **schedule,
            "status_tool": "wrong-status-tool",
        }
        with self.subTest(failure="schedule-validation"), patch.object(
            grips, "_runtime_deploy_self_preflight", return_value=preflight
        ), patch.object(
            grips, "_runtime_deploy_self_schedule", return_value=invalid_schedule
        ), patch.object(
            grips,
            "_runtime_deploy_self_schedule_source_preflight",
            return_value=preflight,
        ), patch.object(
            grips,
            "_runtime_deploy_self_expected_argv_sha256",
            return_value="d" * 64,
        ):
            execution = grips._run_captain_runtime_deploy(
                action,
                {"expected_head": CAPTAIN_HEAD, "delay_seconds": 8},
            )
            self.assertTrue(execution["command_returned"])
            self.assertTrue(execution["mutation_outcome_unknown"])
            self.assertTrue(execution["local_mutation_outcome_unknown"])
            self.assertTrue(execution["local_mutation_observed"])
            self.assertEqual(execution["local_mutation_evidence"], reconciliation)
            self.assertIn(
                "runtime_deploy_status_tool_missing",
                execution["post_verify_errors"],
            )

    def test_captain_accepts_auto_source_effect_and_four_effect_bundle(self) -> None:
        auto_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_auto_source_effect",
            "expected_head": CAPTAIN_HEAD,
            "repository": "/tmp/pr1366-auto-source",
            "owner_id": f"runtime-deploy-source:{CAPTAIN_HEAD[:12]}:bbbbbbbbbbbb",
            "generation": "bbbbbbbbbbbb",
            "path_resource_key": "path:/tmp/pr1366-auto-source",
            "source_identity_sha256": "d" * 64,
            "lifecycle_checkout_key": "e" * 64,
            "uncertainty_fence_id": "f" * 32,
            "uncertainty_evidence_sha256": "1" * 64,
            "effect_observed": True,
        }
        auto = {
            **auto_material,
            "evidence_sha256": grips.sha256_json(auto_material),
        }
        self.assertTrue(
            grips._runtime_deploy_local_mutation_evidence_valid(
                auto,
                expected_job_prefix="grabowski-job-",
                expected_head=CAPTAIN_HEAD,
            )
        )
        wrong_prefix = "0" * 12 if CAPTAIN_HEAD[:12] != "0" * 12 else "1" * 12
        forged_material = {
            **auto_material,
            "owner_id": f"runtime-deploy-source:{wrong_prefix}:bbbbbbbbbbbb",
        }
        forged = {
            **forged_material,
            "evidence_sha256": grips.sha256_json(forged_material),
        }
        self.assertFalse(
            grips._runtime_deploy_local_mutation_evidence_valid(
                forged,
                expected_job_prefix="grabowski-job-",
                expected_head=CAPTAIN_HEAD,
            )
        )
        reconciliation_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_stale_pending_reconciliation",
            "unit": "grabowski-job-123456abcdef",
            "dispatch_outcome": "not_started",
            "deploy_index_updated": True,
            "audit_recorded": True,
            "index_updated_at_unix": 1,
        }
        reconciliation = {
            **reconciliation_material,
            "evidence_sha256": grips.sha256_json(reconciliation_material),
        }
        refresh_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_origin_main_refresh",
            "canonical_repository": "/home/alex/repos/grabowski",
            "expected_head": CAPTAIN_HEAD,
            "previous_head": "a" * 40,
            "previous_branch": "main",
            "previous_origin_main": "b" * 40,
            "observed_origin_main": CAPTAIN_HEAD,
            "owner_id": "runtime-deploy-ref:test",
            "operation_resource_key": "repo:/home/alex/repos/grabowski:operation:runtime-deploy-origin-main-refresh",
            "canonical_resource_key": "path:/home/alex/repos/grabowski",
            "common_dir_resource_key": "path:/home/alex/repos/grabowski/.git",
            "objects_resource_key": "path:/home/alex/repos/grabowski/.git/objects",
            "origin_main_ref_resource_key": "path:/home/alex/repos/grabowski/.git/refs/remotes/origin/main",
            "fetch": {"returncode": 0, "timed_out": False},
            "update_ref": {
                "returncode": 0,
                "timed_out": False,
                "reported_success": True,
            },
            "public_github_main": {
                "before_fetch": CAPTAIN_HEAD,
                "after_fetch": CAPTAIN_HEAD,
                "after_cas": CAPTAIN_HEAD,
            },
        }
        refresh = {
            **refresh_material,
            "receipt_sha256": grips.sha256_json(refresh_material),
        }
        authority_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_rootbroker_authority_effect",
            "expected_head": CAPTAIN_HEAD,
            "outcome": "succeeded",
            "attested_head": CAPTAIN_HEAD,
            "effect_started": True,
            "request_id": "rootbroker-test",
            "reference_sha256": "c" * 64,
        }
        authority = {
            **authority_material,
            "evidence_sha256": grips.sha256_json(authority_material),
        }
        self.assertTrue(
            grips._runtime_deploy_local_mutation_evidence_valid(
                authority,
                expected_job_prefix="grabowski-job-",
                expected_head=CAPTAIN_HEAD,
            )
        )
        wrong_head = "0" * 40 if CAPTAIN_HEAD != "0" * 40 else "1" * 40
        for attested_head in (None, wrong_head):
            forged_material = {
                **authority_material,
                "attested_head": attested_head,
            }
            forged = {
                **forged_material,
                "evidence_sha256": grips.sha256_json(forged_material),
            }
            self.assertFalse(
                grips._runtime_deploy_local_mutation_evidence_valid(
                    forged,
                    expected_job_prefix="grabowski-job-",
                    expected_head=CAPTAIN_HEAD,
                )
            )
        bundle_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_local_mutation_bundle",
            "effects": [reconciliation, refresh, authority, auto],
        }
        bundle = {
            **bundle_material,
            "evidence_sha256": grips.sha256_json(bundle_material),
        }
        self.assertTrue(
            grips._runtime_deploy_local_mutation_evidence_valid(
                bundle,
                expected_job_prefix="grabowski-job-",
                expected_head=CAPTAIN_HEAD,
            )
        )
        five_material = {**bundle_material, "effects": [self._promotion_evidence(), *bundle_material["effects"]]}
        five = {**five_material, "evidence_sha256": grips.sha256_json(five_material)}
        self.assertTrue(
            grips._runtime_deploy_local_mutation_evidence_valid(
                five, expected_job_prefix="grabowski-job-", expected_head=CAPTAIN_HEAD
            )
        )
        for effects in (
            [*five_material["effects"][1:], five_material["effects"][0]],
            [five_material["effects"][0], five_material["effects"][0]],
        ):
            invalid_material = {**five_material, "effects": effects}
            invalid = {**invalid_material, "evidence_sha256": grips.sha256_json(invalid_material)}
            self.assertFalse(
                grips._runtime_deploy_local_mutation_evidence_valid(
                    invalid, expected_job_prefix="grabowski-job-", expected_head=CAPTAIN_HEAD
                )
            )
    def test_origin_main_refresh_post_cas_failure_reports_observed_effect(self) -> None:
        canonical = Path("/tmp/pr1366-origin-main-effect")
        common = canonical / ".git"
        expected = "d" * 40
        current = "a" * 40
        previous_origin = "b" * 40
        owner = "runtime-deploy-ref:dddddddddddd:abc123def456"
        plan = {
            "canonical_repository": canonical,
            "owner_id": owner,
            "operation_key": f"repo:{canonical}:operation:runtime-deploy-origin-main-refresh",
            "canonical_key": f"path:{canonical}",
            "common_dir_key": f"path:{common}",
            "objects_key": f"path:{common / 'objects'}",
            "origin_main_ref_key": f"path:{common / 'refs/remotes/origin/main'}",
        }
        leases = [
            {
                "resource_key": key,
                "owner_id": owner,
                "acquired_at_unix": 10,
                "updated_at_unix": 10,
                "expires_at_unix": 100,
                "metadata_sha256": str(index) * 64,
            }
            for index, key in enumerate(
                [
                    plan["operation_key"],
                    plan["canonical_key"],
                    plan["common_dir_key"],
                    plan["objects_key"],
                    plan["origin_main_ref_key"],
                ],
                start=1,
            )
        ]
        initial = {
            "canonical_repository": str(canonical),
            "current_head": current,
            "current_branch": "feature/active-work",
            "target_head": expected,
            "origin_main": previous_origin,
            "clean": True,
            "shallow": False,
            "lease_evidence": {
                "resource_key": f"path:{canonical}",
                "lease": None,
            },
        }
        locked = dict(initial)
        after_cas = {**initial, "origin_main": expected}
        with patch.object(
            SELF_DEPLOY, "_origin_main_refresh_plan", return_value=plan
        ), patch.object(
            SELF_DEPLOY,
            "_acquire_origin_main_refresh_resources",
            return_value={"leases": leases},
        ), patch.object(
            SELF_DEPLOY,
            "_release_origin_main_refresh_resources",
            return_value={"released": leases},
        ) as release, patch.object(
            SELF_DEPLOY,
            "_canonical_main_refresh_candidate",
            side_effect=[locked, locked, after_cas],
        ), patch.object(
            SELF_DEPLOY,
            "_fresh_public_github_main",
            side_effect=[expected, expected, expected],
        ), patch.object(
            SELF_DEPLOY,
            "_mutating_git_result",
            side_effect=[_result(""), _result("")],
        ), patch.object(
            SELF_DEPLOY,
            "_git_result",
            side_effect=[
                _result(expected),
                _result("", 0),
                _result(expected),
            ],
        ), patch.object(
            SELF_DEPLOY,
            "_require_target_deploy_runner",
        ) as target_runner, patch.object(
            SELF_DEPLOY,
            "_append_deploy_audit",
            side_effect=OSError("audit unavailable after CAS"),
        ):
            with self.assertRaises(
                SELF_DEPLOY.DeployScheduleFailureAfterLocalMutation
            ) as raised:
                SELF_DEPLOY._refresh_canonical_origin_main(expected, initial)
        target_runner.assert_called_once_with(canonical, expected)
        release.assert_called_once()
        evidence = raised.exception.local_mutation_evidence
        self.assertEqual(
            evidence["kind"],
            "grabowski_runtime_deploy_origin_main_refresh_effect",
        )
        self.assertTrue(evidence["effect_observed"])
        self.assertEqual(evidence["expected_head"], expected)
        self.assertEqual(evidence["observed_origin_main"], expected)
        self.assertEqual(
            evidence["public_github_main"],
            {"before_fetch": expected, "after_fetch": expected},
        )
        self.assertTrue(
            grips._runtime_deploy_local_mutation_evidence_valid(
                evidence,
                expected_job_prefix="grabowski-job-",
                expected_head=expected,
            )
        )
        forged_material = {
            key: value
            for key, value in evidence.items()
            if key != "evidence_sha256"
        }
        forged_material["observed_origin_main"] = "0" * 40
        forged = {
            **forged_material,
            "evidence_sha256": grips.sha256_json(forged_material),
        }
        self.assertFalse(
            grips._runtime_deploy_local_mutation_evidence_valid(
                forged,
                expected_job_prefix="grabowski-job-",
                expected_head=expected,
            )
        )

    def test_scheduler_bundles_reconciliation_with_refresh_helper_effect_failure(
        self,
    ) -> None:
        repo = Path("/home/alex/repos/grabowski")
        expected = "d" * 40
        reconciliation_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_stale_pending_reconciliation",
            "unit": "grabowski-job-123456abcdef",
            "dispatch_outcome": "not_started",
            "deploy_index_updated": True,
            "audit_recorded": True,
            "index_updated_at_unix": 1,
        }
        reconciliation = {
            **reconciliation_material,
            "evidence_sha256": SELF_DEPLOY._source_identity_sha256(
                reconciliation_material
            ),
        }
        refresh_effect_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_origin_main_refresh_effect",
            "canonical_repository": str(repo),
            "expected_head": expected,
            "previous_head": "a" * 40,
            "previous_branch": "main",
            "previous_origin_main": "b" * 40,
            "observed_origin_main": expected,
            "owner_id": "runtime-deploy-ref:dddddddddddd:abc123def456",
            "operation_resource_key": (
                f"repo:{repo}:operation:runtime-deploy-origin-main-refresh"
            ),
            "canonical_resource_key": f"path:{repo}",
            "common_dir_resource_key": f"path:{repo / '.git'}",
            "objects_resource_key": f"path:{repo / '.git' / 'objects'}",
            "origin_main_ref_resource_key": (
                f"path:{repo / '.git' / 'refs/remotes/origin/main'}"
            ),
            "fetch": {"returncode": 0, "timed_out": False},
            "update_ref": {
                "returncode": 0,
                "timed_out": False,
                "reported_success": True,
            },
            "public_github_main": {
                "before_fetch": expected,
                "after_fetch": expected,
            },
            "effect_observed": True,
        }
        refresh_effect = {
            **refresh_effect_material,
            "evidence_sha256": SELF_DEPLOY._source_identity_sha256(
                refresh_effect_material
            ),
        }
        refresh_failure = SELF_DEPLOY.DeployScheduleFailureAfterLocalMutation(
            "post-CAS audit unavailable",
            local_mutation_evidence=refresh_effect,
        )
        refresh_candidate = {
            "canonical_repository": str(repo),
            "current_head": expected,
            "current_branch": "main",
            "target_head": expected,
            "origin_main": "b" * 40,
            "clean": True,
        }
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            side_effect=[RuntimeError("canonical source needs refresh")],
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(
            SELF_DEPLOY, "_fresh_public_github_main", return_value=expected
        ), patch.object(
            SELF_DEPLOY,
            "_canonical_stale_main_snapshot",
            side_effect=RuntimeError("not a stale-main materialization case"),
        ), patch.object(
            SELF_DEPLOY,
            "_canonical_main_refresh_candidate",
            return_value=refresh_candidate,
        ), patch.object(
            SELF_DEPLOY,
            "inflight_runtime_job_evidence",
            return_value={
                "error": None,
                "inflight_units": [],
                "stale_pending_reconciliation": reconciliation,
            },
        ), patch.object(
            SELF_DEPLOY,
            "_refresh_canonical_origin_main",
            side_effect=refresh_failure,
        ):
            with self.assertRaises(
                SELF_DEPLOY.DeployScheduleFailureAfterLocalMutation
            ) as raised:
                SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 8)
        evidence = raised.exception.local_mutation_evidence
        self.assertEqual(
            evidence["kind"],
            "grabowski_runtime_deploy_local_mutation_bundle",
        )
        self.assertEqual(
            [item["kind"] for item in evidence["effects"]],
            [
                "grabowski_runtime_deploy_stale_pending_reconciliation",
                "grabowski_runtime_deploy_origin_main_refresh_effect",
            ],
        )
        self.assertTrue(
            grips._runtime_deploy_local_mutation_evidence_valid(
                evidence,
                expected_job_prefix="grabowski-job-",
                expected_head=expected,
            )
        )




if __name__ == "__main__":
    unittest.main()
