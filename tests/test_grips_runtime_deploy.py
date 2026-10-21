from __future__ import annotations

from contextlib import contextmanager, nullcontext
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
import grabowski_release_admission as release_admission  # noqa: E402


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
        ), patch.object(
            real_deploy, "_require_release_source_admission",
            return_value={"independent_review_required": False},
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
        ), patch.object(
            real_deploy, "_require_release_source_admission",
            return_value={"independent_review_required": False},
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
    def _raw_change(path: str) -> str:
        return f":100644 100644 {'a'*40} {'b'*40} M\x00{path}\x00"

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

    def test_release_ancestry_git_read_forces_c_locale_independent_of_host(self) -> None:
        repository = Path("/fixture/canonical")
        expected = "b" * 40
        arguments = ("merge-base", "--is-ancestor", "a" * 40, expected)
        with (
            patch.dict("os.environ", {"LANG": "fr_FR.UTF-8", "LC_ALL": "fr_FR.UTF-8"}),
            patch.object(
                real_deploy.read_surface, "_run_read",
                return_value=self._git_success(""),
            ) as read,
        ):
            observed = real_deploy._git_result(
                repository, *arguments, c_locale=True
            )
        self.assertEqual(observed["returncode"], 0)
        read.assert_called_once_with(
            ["/usr/bin/env", "LC_ALL=C",
             *real_deploy.read_surface._git_command(repository, *arguments)],
            cwd=repository,
            timeout_seconds=30,
            max_output_bytes=65_536,
        )

    def test_only_exact_missing_target_with_present_serving_allows_import_path(self) -> None:
        """A failed merge-base never alone authorizes an ODB mutation."""
        deploy = real_deploy
        expected = "b" * 40
        serving = "a" * 40
        ancestor_missing_target = {
            **self._git_success(""),
            "returncode": 128,
            "stderr": f"fatal: Not a valid commit name {expected}\n",
        }
        serving_present = self._git_success(serving + "\n")
        missing = {**self._git_success(""), "returncode": 1}
        cases = (
            ("target-absent", ancestor_missing_target, serving_present, missing, True),
            ("serving-absent", ancestor_missing_target, missing, missing, False),
            ("serving-wrong-oid", ancestor_missing_target,
             self._git_success("c" * 40 + "\n"), missing, False),
            ("target-present", ancestor_missing_target, serving_present,
             self._git_success(expected + "\n"), False),
            ("unrelated-git-error", {**ancestor_missing_target,
             "stderr": "fatal: corrupt pack index\n"}, serving_present, missing, False),
            ("not-ancestor", {**ancestor_missing_target,
             "returncode": 1, "stderr": ""}, serving_present, missing, False),
            ("timed-out", {**ancestor_missing_target,
             "timed_out": True}, serving_present, missing, False),
            ("truncated", {**ancestor_missing_target,
             "stderr_truncated": True}, serving_present, missing, False),
        )
        for label, ancestor, observed_serving, observed_target, eligible in cases:
            with (
                self.subTest(case=label),
                patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
                patch.object(deploy.serving_process, "identity", return_value=self._serving()),
                patch.object(deploy, "_git_result",
                             side_effect=[ancestor, observed_serving, observed_target]) as git,
            ):
                with self.assertRaises(deploy.DeploySchedulePreEffectRefusal) as blocked:
                    deploy._require_release_source_admission(expected)
            self.assertEqual(
                str(blocked.exception) == "release admission blocked: source ancestry is unproved",
                eligible,
            )
            self.assertEqual({"c_locale": True}, git.call_args_list[0].kwargs)
            if eligible:
                self.assertEqual(3, git.call_count)
                self.assertEqual(
                    ("rev-parse", "--verify", "--quiet", f"{serving}^{{commit}}"),
                    git.call_args_list[1].args[1:],
                )
                self.assertEqual(
                    ("rev-parse", "--verify", "--quiet", f"{expected}^{{commit}}"),
                    git.call_args_list[2].args[1:],
                )

    def test_other_ancestry_error_is_never_a_scheduler_fetch_permission(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy, "_require_release_source_admission",
                         side_effect=deploy.DeploySchedulePreEffectRefusal(
                             "release admission blocked: ancestor check failed"
                         )),
            patch.object(deploy, "_deploy_schedule_lock") as lock,
            patch.object(deploy, "_protected_release_admission_target_snapshot") as snapshot,
            patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
        ):
            with self.assertRaisesRegex(deploy.DeploySchedulePreEffectRefusal,
                                        "ancestor check failed"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    "b" * 40, local_mutation_tracker={}
                )
        lock.assert_not_called()
        snapshot.assert_not_called()
        fetch.assert_not_called()
        broker.assert_not_called()

    def test_authoritative_release_admission_is_fenced_by_exact_odb_leases(self) -> None:
        """Actual in-lock policy read occurs between owner-bound lease acquire/closeout."""
        deploy = real_deploy
        expected = "b" * 40
        repo = Path("/fixture/canonical")
        kinds = ("operation_key", "canonical_key", "common_dir_key",
                 "objects_key", "origin_main_ref_key")
        plan = {
            "canonical_repository": repo, "owner_id": "fixture:leased-admission",
            **{kind: f"fixture:{kind}" for kind in kinds},
        }
        keys = [plan[kind] for kind in kinds]
        leases = [{"resource_key": key} for key in keys]
        snapshot = {
            "canonical_repository": str(repo), "current_head": "a"*40,
            "current_branch": "main", "target_head": expected,
            "origin_main": "c"*40, "target_object_present": True,
            "clean": True, "shallow": False,
        }
        admitted = {
            "status": "non-runtime-documentation",
            "target_repo_head": expected,
            "serving_repo_head": "a"*40,
            "independent_review_required": False,
            "changed_path_count": 1,
        }
        for label, alternate, refusal in (
            ("success", snapshot, False),
            ("ref-drift", {**snapshot, "origin_main": "d"*40}, False),
            ("policy-refusal", snapshot, True),
            ("unbound-policy-result", snapshot, False),
        ):
            events: list[str] = []
            def source_policy(head: str) -> dict:
                self.assertEqual(expected, head)
                events.append("admission")
                if refusal:
                    raise deploy.DeploySchedulePreEffectRefusal("source R3 denied")
                if label == "unbound-policy-result":
                    return {"status": "non-runtime-documentation"}
                return admitted
            def closeout(_plan, resource_keys, observed_leases) -> dict:
                events.append("release")
                self.assertEqual(keys, resource_keys)
                self.assertEqual(leases, observed_leases)
                return {"released": list(leases)}
            with (
                self.subTest(case=label),
                patch.object(deploy, "_origin_main_refresh_plan", return_value=plan),
                patch.object(deploy, "_acquire_origin_main_refresh_resources",
                             return_value={"leases": leases}) as acquire,
                patch.object(deploy, "_require_origin_main_refresh_checkout_certainty") as certain,
                patch.object(deploy, "_canonical_main_refresh_candidate",
                             side_effect=[snapshot, alternate]) as state,
                patch.object(deploy, "_require_release_source_admission",
                             side_effect=source_policy),
                patch.object(deploy, "_release_origin_main_refresh_resources",
                             side_effect=closeout) as close,
            ):
                if refusal or alternate is not snapshot or label == "unbound-policy-result":
                    with self.assertRaises(deploy.DeploySchedulePreEffectRefusal):
                        deploy._require_release_source_admission_under_lease(expected)
                else:
                    self.assertEqual(
                        admitted, deploy._require_release_source_admission_under_lease(expected)
                    )
            acquire.assert_called_once_with(plan, expected)
            certain.assert_called_once_with(plan)
            self.assertEqual(1 if refusal or label == "unbound-policy-result" else 2, state.call_count)
            close.assert_called_once()
            self.assertEqual(["admission", "release"], events)

    def test_scheduler_never_uses_early_approval_when_lease_readmission_denies(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        with (
            patch.object(deploy, "_require_release_source_admission",
                         return_value={"status": "non-runtime-documentation"}) as early,
            patch.object(deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(deploy, "_require_release_source_admission_under_lease",
                         side_effect=deploy.DeploySchedulePreEffectRefusal(
                             "protected source lease unavailable"
                         )) as protected,
            patch.object(deploy, "_fresh_public_github_main") as public,
            patch.object(deploy, "inflight_runtime_job_evidence") as inflight,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
        ):
            with self.assertRaisesRegex(RuntimeError, "protected source lease"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker={},
                )
        early.assert_called_once_with(expected)
        protected.assert_called_once_with(expected)
        public.assert_not_called()
        inflight.assert_not_called()
        broker.assert_not_called()

    def test_docs_git_modes_must_be_plain_regular_files(self) -> None:
        """A docs/*.md suffix cannot legalize an executable, symlink or gitlink."""
        deploy = real_deploy
        def raw(old: str, new: str, status: str) -> str:
            return f":{old} {new} {'0'*40} {'a'*40} {status}\x00docs/guide.md\x00"
        for before, after, status, allowed in (
            ("000000", "100644", "A", True),
            ("100644", "100644", "M", True),
            ("100644", "000000", "D", True),
            ("000000", "100755", "A", False),
            ("000000", "120000", "A", False),
            ("000000", "160000", "A", False),
            ("100644", "100755", "M", False),
            ("120000", "100644", "T", False),
        ):
            with (
                self.subTest(before=before, after=after, status=status),
                patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
                patch.object(deploy.serving_process, "identity", return_value=self._serving()),
                patch.object(deploy, "_git_result", side_effect=[
                    self._git_success(""), self._git_success(raw(before, after, status)),
                ]),
            ):
                if allowed:
                    # Regular Git modes are not proof of inert validation input.
                    with self.assertRaisesRegex(
                        deploy.DeploySchedulePreEffectRefusal,
                        "release review admission missing",
                    ):
                        deploy._require_release_source_admission("b" * 40)
                else:
                    with self.assertRaises(deploy.DeploySchedulePreEffectRefusal):
                        deploy._require_release_source_admission("b"*40)

    def test_real_git_replace_ref_cannot_make_runtime_change_documentation_only(self) -> None:
        """Exercise the actual self-deploy Git read path, not only its helper."""
        import subprocess
        import tempfile

        deploy = real_deploy
        with tempfile.TemporaryDirectory(prefix="grabowski-release-replace-admission-") as folder:
            canonical = Path(folder)

            def git(*args: str) -> str:
                completed = subprocess.run(
                    ["git", "-C", str(canonical), *args],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=True, timeout=15,
                )
                return completed.stdout.decode("utf-8").strip()

            git("init", "-q")
            git("config", "user.name", "Release Admission Test")
            git("config", "user.email", "admission@invalid.example")
            (canonical / "docs").mkdir()
            (canonical / "docs/guide.md").write_text("stable\\n")
            git("add", "--", "docs/guide.md")
            git("commit", "-qm", "base")
            base_head = git("rev-parse", "HEAD")
            (canonical / "src").mkdir()
            (canonical / "src/runtime.py").write_text("SOURCE_CHANGED = True\\n")
            git("add", "--", "src/runtime.py")
            git("commit", "-qm", "runtime change")
            expected_head = git("rev-parse", "HEAD")
            git("replace", expected_head, base_head)

            manifest = {**self._deployed(), "repo_head": base_head}
            process = {**self._serving(), "process_repo_head": base_head}
            with (
                patch.object(deploy, "CANONICAL_REPOSITORY", canonical),
                patch.object(deploy.base, "_deployment_metadata", return_value=manifest),
                patch.object(deploy.serving_process, "identity", return_value=process),
            ):
                with self.assertRaisesRegex(RuntimeError, "release review admission missing"):
                    deploy._require_release_source_admission(expected_head)

    def test_import_effect_precedes_index_reconciliation_in_captain_bundle(self) -> None:
        """The literal tracker emission order must be accepted, not forged."""
        head = "b"*40
        resources = {
            "canonical_repository": "/fixture/canonical",
            "expected_head": head, "previous_head": "a"*40,
            "previous_branch": "main", "previous_origin_main": "c"*40,
            "owner_id": "owner:fixture",
            "operation_resource_key": "operation:test",
            "canonical_resource_key": "path:/fixture/canonical",
            "common_dir_resource_key": "path:/fixture/canonical/.git",
            "objects_resource_key": "path:/fixture/canonical/.git/objects",
            "origin_main_ref_resource_key": "path:/fixture/canonical/.git/refs/remotes/origin/main",
        }
        imported_material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_origin_main_fetch_effect",
            **resources,
            "target_object": {"before_fetch_present": False, "after_fetch_commit": head},
            "fetch": {"returncode": 0, "timed_out": False},
            "public_github_main": {"before_fetch": head},
            "effect_observed": True,
        }
        imported = {**imported_material, "evidence_sha256": grips.sha256_json(imported_material)}
        # A fresh ODB fetch inside ref-refresh follows index reconciliation;
        # it is not the admission-only fetch recorded before the index.
        late_material = {
            **imported_material,
            "kind": "grabowski_runtime_deploy_origin_main_refresh_fetch_effect",
        }
        late_import = {
            **late_material, "evidence_sha256": grips.sha256_json(late_material)
        }
        promotion = {"schema_version": 1, "kind": "grabowski_runtime_deploy_pending_unit_promotion"}
        reconciliation = {"schema_version": 1, "kind": "grabowski_runtime_deploy_stale_pending_reconciliation"}
        def accepts(effects):
            material = {
                "schema_version": 1,
                "kind": "grabowski_runtime_deploy_local_mutation_bundle",
                "effects": effects,
            }
            bundle = {**material, "evidence_sha256": grips.sha256_json(material)}
            return grips._runtime_deploy_local_mutation_evidence_valid(
                bundle, expected_head=head, expected_job_prefix="grabowski-job-"
            )
        with (
            patch.object(grips, "_runtime_deploy_pending_unit_promotion_valid",
                         side_effect=lambda evidence, **kwargs: isinstance(evidence, dict) and
                         evidence.get("kind") == "grabowski_runtime_deploy_pending_unit_promotion"),
            patch.object(grips, "_runtime_deploy_stale_pending_reconciliation_valid",
                         side_effect=lambda evidence, **kwargs: isinstance(evidence, dict) and
                         evidence.get("kind") == "grabowski_runtime_deploy_stale_pending_reconciliation"),
        ):
            self.assertTrue(accepts([imported, promotion]))
            self.assertTrue(accepts([imported, reconciliation]))
            self.assertTrue(accepts([imported, promotion, reconciliation]))
            self.assertTrue(accepts([promotion, late_import]))
            self.assertTrue(accepts([reconciliation, late_import]))
            self.assertTrue(accepts([imported, promotion, late_import]))
            self.assertFalse(accepts([late_import, promotion]))
            self.assertFalse(accepts([late_import, imported]))
            self.assertFalse(accepts([late_import, late_import]))
            self.assertFalse(accepts([promotion, imported]))
            self.assertFalse(accepts([imported, promotion, promotion]))

    def test_import_evidence_survives_ref_refresh_preeffect_denial(self) -> None:
        """An already completed object import is not lost on a later typed refusal."""
        deploy = real_deploy
        expected = "b"*40
        imported = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_origin_main_fetch_effect",
            "expected_head": expected,
            "evidence_sha256": "a"*64,
        }
        reconciliation = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_stale_pending_reconciliation",
            "evidence_sha256": "c"*64,
        }
        tracker = {"admission_target_fetch": imported}
        candidate = {
            "origin_main": "c"*40,
            "current_head": expected,
            "current_branch": "main",
            "canonical_repository": str(deploy.CANONICAL_REPOSITORY),
        }
        with (
            patch.object(deploy, "_require_release_source_admission_under_lease",
                         side_effect=lambda head: deploy._require_release_source_admission(head)),
            patch.object(deploy, "_require_release_source_admission", return_value={
                "status": "non-runtime-documentation",
                "independent_review_required": False,
                "serving_repo_head": "a" * 40,
                "target_repo_head": expected,
                "changed_path_count": 1,
            }),
            patch.object(deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(deploy, "_fresh_public_github_main", return_value=expected),
            patch.object(deploy, "_deployment_source_preflight",
                         side_effect=RuntimeError("canonical source drift")),
            patch.object(deploy, "_canonical_stale_main_snapshot",
                         side_effect=RuntimeError("stale main")),
            patch.object(deploy, "_canonical_main_refresh_candidate", return_value=candidate),
            patch.object(deploy, "inflight_runtime_job_evidence", return_value={
                "error": None, "inflight_units": [],
                "stale_pending_reconciliation": reconciliation,
            }),
            patch.object(deploy, "_refresh_canonical_origin_main",
                         side_effect=deploy.DeploySchedulePreEffectRefusal("ref locked")),
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
        ):
            with self.assertRaises(deploy.DeploySchedulePreEffectRefusal) as blocked:
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker=tracker
                )
        record = blocked.exception.local_mutation_evidence
        self.assertEqual("grabowski_runtime_deploy_local_mutation_bundle", record["kind"])
        self.assertEqual([imported, reconciliation], record["effects"])
        broker.assert_not_called()

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
                    self._git_success(self._raw_change('src/grabowski_agent_role.py') + self._raw_change('tests/test_agent_role_grok.py')),
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
                side_effect=[self._git_success(""), self._git_success(self._raw_change('docs/guide.md'))],
            ),
        ):
            with self.assertRaisesRegex(
                deploy.DeploySchedulePreEffectRefusal,
                "release review admission missing",
            ):
                deploy._require_release_source_admission("b" * 40)

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
            return {"status": "non-runtime-documentation", "independent_review_required": False, "serving_repo_head": "a" * 40, "target_repo_head": expected, "changed_path_count": 1}

        def fetch(head: str, snapshot: dict, *, local_mutation_tracker: dict) -> None:
            self.assertEqual(expected, head)
            self.assertIs(snapshot["target_object_present"], False)
            self.assertEqual({}, local_mutation_tracker)
            calls.append("fetch")

        def stop_before_effect(head: str) -> str:
            calls.append("public-main-read")
            raise RuntimeError("stop before any effect")

        with (
            patch.object(deploy, "_require_release_source_admission_under_lease",
                         side_effect=lambda head: deploy._require_release_source_admission(head)),
            patch.object(deploy, "_require_release_source_admission", side_effect=admit),
            patch.object(
                deploy, "_protected_release_admission_target_snapshot",
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





    def test_missing_target_snapshot_waits_for_schedule_lock(self) -> None:
        """An in-flight importer must release its leases before the waiter reads status."""
        deploy = real_deploy
        expected = "b" * 40
        calls: list[str] = []

        def admission(_head: str) -> dict:
            calls.append("admission")
            if calls.count("admission") == 1:
                raise deploy.DeploySchedulePreEffectRefusal(
                    "release admission blocked: source ancestry is unproved"
                )
            return {"status": "non-runtime-documentation", "independent_review_required": False, "serving_repo_head": "a" * 40, "target_repo_head": expected, "changed_path_count": 1}

        @contextmanager
        def lock():
            calls.append("lock-enter")
            try:
                yield
            finally:
                calls.append("lock-exit")

        def protected_snapshot(_head: str) -> dict:
            self.assertIn("lock-enter", calls)
            calls.append("leased-snapshot")
            return {"target_object_present": True}

        def stop_before_effect(_head: str) -> str:
            calls.append("public-main")
            raise RuntimeError("stop before effect")

        with (
            patch.object(deploy, "_require_release_source_admission_under_lease",
                         side_effect=lambda head: deploy._require_release_source_admission(head)),
            patch.object(deploy, "_require_release_source_admission", side_effect=admission),
            patch.object(deploy, "_deploy_schedule_lock", side_effect=lock),
            patch.object(deploy, "_protected_release_admission_target_snapshot",
                         side_effect=protected_snapshot, create=True),
            patch.object(deploy, "_canonical_main_refresh_candidate",
                         side_effect=AssertionError("unguarded Git status")) as porcelain,
            patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
            patch.object(deploy, "_fresh_public_github_main", side_effect=stop_before_effect),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop before effect"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker={},
                )
        self.assertEqual(
            ["admission", "lock-enter", "leased-snapshot", "admission", "public-main", "lock-exit"],
            calls,
        )
        porcelain.assert_not_called()
        fetch.assert_not_called()

    def test_guarded_missing_target_snapshot_owns_checkout_odb_leases(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        repo = Path("/fixture/canonical")
        keys = ("operation_key", "canonical_key", "common_dir_key",
                "objects_key", "origin_main_ref_key")
        plan = {"canonical_repository": repo, "owner_id": "fixture:review-snapshot",
                **{name: f"fixture:{name}" for name in keys}}
        leases = [{"resource_key": plan[k]} for k in keys]
        events: list[str] = []
        snapshot = {
            "canonical_repository": str(repo),
            "target_head": expected,
            "target_object_present": False,
        }

        def acquire(_plan: dict, _head: str) -> dict:
            events.append("acquire")
            return {"leases": leases}

        def verify(_plan: dict) -> None:
            events.append("verify-checkout")

        def observe(head: str, owner: str) -> dict:
            self.assertEqual((expected, plan["owner_id"]), (head, owner))
            events.append("status-under-lease")
            return snapshot

        def release(_plan: dict, resource_keys: list, observed: list) -> dict:
            self.assertEqual([plan[k] for k in keys], resource_keys)
            self.assertEqual(leases, observed)
            events.append("release")
            return {"released": leases}

        with (
            patch.object(deploy, "_origin_main_refresh_plan", return_value=plan),
            patch.object(deploy, "_acquire_origin_main_refresh_resources", side_effect=acquire),
            patch.object(deploy, "_lease_for_key", side_effect=lambda _acq, key: {"resource_key": key}),
            patch.object(deploy, "_require_origin_main_refresh_checkout_certainty", side_effect=verify),
            patch.object(deploy, "_canonical_main_refresh_candidate", side_effect=observe),
            patch.object(deploy, "_release_origin_main_refresh_resources", side_effect=release),
        ):
            self.assertEqual(
                snapshot, deploy._protected_release_admission_target_snapshot(expected)
            )
        self.assertEqual(
            ["acquire", "verify-checkout", "status-under-lease", "release"], events
        )

    def test_guarded_missing_target_snapshot_rejects_lease_conflict_before_status(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy, "_origin_main_refresh_plan", return_value={
                "operation_key": "fixture:operation",
                "canonical_key": "fixture:canonical",
                "common_dir_key": "fixture:common",
                "objects_key": "fixture:objects",
                "origin_main_ref_key": "fixture:ref",
            }),
            patch.object(
                deploy, "_acquire_origin_main_refresh_resources",
                side_effect=deploy.DeploySchedulePreEffectRefusal("resource busy"),
            ),
            patch.object(deploy, "_canonical_main_refresh_candidate") as porcelain,
        ):
            with self.assertRaisesRegex(RuntimeError, "resource busy"):
                deploy._protected_release_admission_target_snapshot("b" * 40)
        porcelain.assert_not_called()

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
            return {"status": "non-runtime-documentation", "independent_review_required": False, "serving_repo_head": "a" * 40, "target_repo_head": expected, "changed_path_count": 1}

        def stop_before_effect(head: str) -> str:
            self.assertEqual(expected, head)
            events.append("public-main")
            raise RuntimeError("stop before any effect")

        with (
            patch.object(deploy, "_require_release_source_admission_under_lease",
                         side_effect=lambda head: deploy._require_release_source_admission(head)),
            patch.object(deploy, "_require_release_source_admission", side_effect=admission),
            patch.object(deploy, "_protected_release_admission_target_snapshot",
                         return_value=reobserved) as candidate,
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
        candidate.assert_called_once_with(expected)
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
            patch.object(deploy, "_require_release_source_admission_under_lease",
                         side_effect=lambda head: deploy._require_release_source_admission(head)),
            patch.object(deploy, "_require_release_source_admission",
                         side_effect=deploy.DeploySchedulePreEffectRefusal(
                             "release admission blocked: source ancestry is unproved"
                         )) as admission,
            patch.object(deploy, "_protected_release_admission_target_snapshot",
                         return_value=drifted),
            patch.object(deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
            patch.object(deploy, "_fresh_public_github_main") as public,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as rootbroker,
        ):
            with self.assertRaisesRegex(RuntimeError, "source ancestry"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker={}
                )
        self.assertEqual(2, admission.call_count)
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
                patch.object(deploy, "_require_release_source_admission_under_lease",
                             side_effect=lambda head: deploy._require_release_source_admission(head)),
                self.subTest(message=message),
                patch.object(
                    deploy, "_require_release_source_admission",
                    side_effect=deploy.DeploySchedulePreEffectRefusal(message),
                ),
                patch.object(
                    deploy, "_protected_release_admission_target_snapshot",
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
            self.assertEqual(1 if need_snapshot else 0, schedule_lock.call_count)
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

    def test_origin_main_renewal_requires_live_exact_lease_snapshots(self) -> None:
        deploy = real_deploy
        names = ("operation_key", "canonical_key", "common_dir_key",
                 "objects_key", "origin_main_ref_key")
        plan = {
            "owner_id": "fixture:post-audit",
            **{name: f"fixture:{name}" for name in names},
        }
        keys = [plan[name] for name in names]
        expires = int(deploy.time.time()) + 120
        prior = [
            {
                "resource_key": key, "owner_id": plan["owner_id"],
                "acquired_at_unix": 1, "updated_at_unix": 2,
                "expires_at_unix": expires, "metadata_sha256": "a" * 64,
            }
            for key in keys
        ]
        newer = [{**lease, "expires_at_unix": expires + 1800} for lease in prior]
        resources = types.ModuleType("grabowski_resources")
        resources.renew_resources = Mock(return_value={
            "owner_id": plan["owner_id"], "snapshot_guarded": True,
            "leases": newer,
        })
        with patch.dict(sys.modules, {"grabowski_resources": resources}):
            renewal = deploy._renew_origin_main_refresh_resources(
                plan, keys, {"leases": prior}
            )
        self.assertEqual(newer, renewal["leases"])
        resources.renew_resources.assert_called_once_with(
            plan["owner_id"], keys,
            ttl_seconds=deploy.ORIGIN_MAIN_REFRESH_LEASE_TTL_SECONDS,
            expected_leases=prior,
        )
        for malformed in (
            {"owner_id": plan["owner_id"], "snapshot_guarded": False,
             "leases": newer},
            {"owner_id": plan["owner_id"], "snapshot_guarded": True,
             "leases": newer[:-1]},
            {"owner_id": plan["owner_id"], "snapshot_guarded": True,
             "leases": [{**lease, "expires_at_unix": 0} for lease in newer]},
        ):
            with (
                self.subTest(malformed=malformed),
                patch.object(resources, "renew_resources", return_value=malformed),
                patch.dict(sys.modules, {"grabowski_resources": resources}),
            ):
                with self.assertRaises(deploy.DeploySchedulePreEffectRefusal):
                    deploy._renew_origin_main_refresh_resources(
                        plan, keys, {"leases": prior}
                    )

    def test_expired_origin_main_leases_block_git_before_fetch_after_audit(self) -> None:
        deploy = real_deploy
        expected = "b" * 40
        repo = Path("/fixture/canonical")
        snapshot = {
            "canonical_repository": str(repo), "current_head": "a" * 40,
            "current_branch": "main", "target_head": expected,
            "origin_main": "c" * 40, "clean": True,
            "shallow": False, "target_object_present": False,
        }
        fields = ("operation_key", "canonical_key", "common_dir_key",
                  "objects_key", "origin_main_ref_key")
        plan = {
            "canonical_repository": repo, "owner_id": "fixture:after-audit",
            **{key: f"fixture:{key}" for key in fields},
        }
        leases = [{"resource_key": plan[key]} for key in fields]
        tracker: dict = {}
        with (
            patch.object(deploy, "_origin_main_refresh_plan", return_value=plan),
            patch.object(deploy, "_acquire_origin_main_refresh_resources",
                         return_value={"leases": leases}),
            patch.object(deploy, "_lease_for_key",
                         side_effect=lambda _acq, key: {"resource_key": key}),
            patch.object(deploy, "_require_origin_main_refresh_checkout_certainty"),
            patch.object(deploy, "_canonical_main_refresh_candidate", return_value=snapshot),
            patch.object(deploy, "_git_result", return_value=self._git_success("sha1")),
            patch.object(deploy, "_fresh_public_github_main", return_value=expected),
            patch.object(deploy, "_append_deploy_audit") as audit,
            patch.object(deploy, "_renew_origin_main_refresh_resources",
                         side_effect=RuntimeError("Resource lease has expired")) as renew,
            patch.object(deploy, "_mutating_git_result") as fetch,
            patch.object(deploy, "_release_origin_main_refresh_resources",
                         return_value={"released": leases}) as close,
        ):
            with self.assertRaisesRegex(RuntimeError, "Resource lease has expired"):
                deploy._fetch_exact_release_admission_target(
                    expected, snapshot, local_mutation_tracker=tracker
                )
        audit.assert_called_once()
        renew.assert_called_once()
        fetch.assert_not_called()
        close.assert_called_once()
        self.assertEqual({}, tracker)

    def test_import_closeout_rejects_missing_duplicate_or_unbound_lease_keys(self) -> None:
        """A post-fetch closeout cannot claim all resources were released by count alone."""
        deploy = real_deploy
        expected = "b" * 40
        repository = Path("/fixture/canonical")
        snapshot = {
            "canonical_repository": str(repository), "current_head": "a"*40,
            "current_branch": "main", "target_head": expected,
            "origin_main": "c"*40, "clean": True,
            "shallow": False, "target_object_present": False,
        }
        after = {**snapshot, "target_object_present": True}
        kinds = ("operation_key", "canonical_key", "common_dir_key",
                 "objects_key", "origin_main_ref_key")
        plan = {
            "canonical_repository": repository, "owner_id": "fixture:closeout",
            **{kind: f"fixture:{kind}" for kind in kinds},
        }
        valid = [{"resource_key": plan[kind]} for kind in kinds]
        for label, released in (
            ("wrong-key", [{"resource_key": "foreign:lease"}, *valid[1:]]),
            ("duplicate-key", [valid[0], valid[0], *valid[2:]]),
            ("non-object", [None, *valid[1:]]),
        ):
            tracker: dict = {}
            def git_read(repo_arg: Path, *args: str) -> dict:
                self.assertEqual(repository, repo_arg)
                if args == ("rev-parse", "--show-object-format"):
                    return self._git_success("sha1")
                if args == ("rev-parse", "--verify", f"{expected}^{{commit}}"):
                    return self._git_success(expected)
                self.fail(f"unknown read {args}")
            with (
                self.subTest(case=label),
                patch.object(deploy, "_origin_main_refresh_plan", return_value=plan),
                patch.object(deploy, "_acquire_origin_main_refresh_resources",
                             return_value={"leases": valid}),
                patch.object(deploy, "_lease_for_key",
                             side_effect=lambda _acq, key: {"resource_key": key}),
                patch.object(deploy, "_require_origin_main_refresh_checkout_certainty"),
                patch.object(deploy, "_canonical_main_refresh_candidate",
                             side_effect=[snapshot, snapshot, after]),
                patch.object(deploy, "_git_result", side_effect=git_read),
                patch.object(deploy, "_fresh_public_github_main", return_value=expected),
                patch.object(deploy, "_append_deploy_audit"),
                patch.object(deploy, "_renew_origin_main_refresh_resources",
                             return_value={"leases": valid}),
                patch.object(deploy, "_mutating_git_result",
                             return_value=self._git_success("")) as fetch,
                patch.object(deploy, "_release_origin_main_refresh_resources",
                             return_value={"released": released}) as close,
            ):
                with self.assertRaisesRegex(RuntimeError, "lease closeout incomplete"):
                    deploy._fetch_exact_release_admission_target(
                        expected, snapshot, local_mutation_tracker=tracker,
                    )
            fetch.assert_called_once()
            close.assert_called_once()
            self.assertEqual(
                "grabowski_runtime_deploy_origin_main_fetch_effect",
                tracker["admission_target_fetch"]["kind"],
            )

    def test_audit_wait_rechecks_checkout_and_ref_after_lease_renewal(self) -> None:
        """A renewed lease alone does not authenticate the old checkout snapshot."""
        deploy = real_deploy
        expected = "b" * 40
        repo = Path("/fixture/canonical")
        initial = {
            "canonical_repository": str(repo), "current_head": "a"*40,
            "current_branch": "main", "target_head": expected,
            "origin_main": "c"*40, "clean": True, "shallow": False,
            "target_object_present": False,
        }
        drifted = {**initial, "origin_main": "d"*40}
        fields = ("operation_key", "canonical_key", "common_dir_key",
                  "objects_key", "origin_main_ref_key")
        plan = {
            "canonical_repository": repo, "owner_id": "fixture:audit-ref-drift",
            **{key: f"fixture:{key}" for key in fields},
        }
        leases = [{"resource_key": plan[key]} for key in fields]
        tracker: dict = {}
        with (
            patch.object(deploy, "_origin_main_refresh_plan", return_value=plan),
            patch.object(deploy, "_acquire_origin_main_refresh_resources",
                         return_value={"leases": leases}),
            patch.object(deploy, "_lease_for_key",
                         side_effect=lambda _acq, key: {"resource_key": key}),
            patch.object(deploy, "_require_origin_main_refresh_checkout_certainty") as certain,
            patch.object(deploy, "_canonical_main_refresh_candidate",
                         side_effect=[initial, drifted]) as checkout,
            patch.object(deploy, "_git_result", return_value=self._git_success("sha1")),
            patch.object(deploy, "_fresh_public_github_main", return_value=expected),
            patch.object(deploy, "_append_deploy_audit") as audit,
            patch.object(deploy, "_renew_origin_main_refresh_resources",
                         return_value={"leases": leases}) as renew,
            patch.object(deploy, "_mutating_git_result") as fetch,
            patch.object(deploy, "_release_origin_main_refresh_resources",
                         return_value={"released": leases}) as close,
        ):
            with self.assertRaisesRegex(
                deploy.DeploySchedulePreEffectRefusal, "checkout/ref identity drifted"
            ):
                deploy._fetch_exact_release_admission_target(
                    expected, initial, local_mutation_tracker=tracker,
                )
        self.assertEqual(2, certain.call_count)
        self.assertEqual(2, checkout.call_count)
        audit.assert_called_once()
        renew.assert_called_once()
        fetch.assert_not_called()
        close.assert_called_once()
        self.assertEqual({}, tracker)

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
                        side_effect=[snapshot, snapshot, after],
                    ),
                    patch.object(deploy, "_git_result", side_effect=git_read),
                    patch.object(
                        deploy, "_fresh_public_github_main", return_value=expected,
                    ) as remote,
                    patch.object(deploy, "_renew_origin_main_refresh_resources",
                                 return_value={"leases": []}, create=True) as renew,
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
                self.assertEqual(3, remote.call_count)
                self.assertEqual(2, audit.call_count)
                renew.assert_called_once()
                self.assertEqual("fetch", git_mutate.call_args.args[1])
                self.assertIn("--no-write-fetch-head", git_mutate.call_args.args)
                self.assertNotIn("update-ref", git_mutate.call_args.args)
                self.assertEqual(expected, git_mutate.call_args.args[-1])
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
                         side_effect=[initial, initial, drifted]),
            patch.object(deploy, "_git_result", side_effect=read),
            patch.object(deploy, "_fresh_public_github_main",
                         return_value=expected),
            patch.object(deploy, "_renew_origin_main_refresh_resources",
                         return_value={"leases": []}, create=True) as renew,
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

        completed_import = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_origin_main_fetch_effect",
            "expected_head": expected,
            "status": "mocked-completed-object-import",
        }
        completed_import = {
            **completed_import,
            "evidence_sha256": deploy._source_identity_sha256(completed_import),
        }

        def fetch(head: str, snapshot: dict, *, local_mutation_tracker: dict) -> None:
            calls.append("fetch")
            local_mutation_tracker["admission_target_fetch"] = completed_import

        with (
            patch.object(deploy, "_require_release_source_admission_under_lease",
                         side_effect=lambda head: deploy._require_release_source_admission(head)),
            patch.object(deploy, "_require_release_source_admission", side_effect=admission),
            patch.object(deploy, "_protected_release_admission_target_snapshot",
                         return_value={"target_object_present": False}),
            patch.object(deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(deploy, "_fetch_exact_release_admission_target", side_effect=fetch),
            patch.object(deploy, "_fresh_public_github_main") as remote,
            patch.object(deploy, "inflight_runtime_job_evidence") as index,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
        ):
            with self.assertRaisesRegex(RuntimeError, "independent R3") as raised:
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker={}
                )
        self.assertEqual(
            completed_import, raised.exception.local_mutation_evidence
        )
        self.assertEqual(["admission", "fetch", "admission"], calls)
        remote.assert_not_called()
        index.assert_not_called()
        broker.assert_not_called()

    def test_direct_scheduler_failed_fetch_preserves_digest_bound_unknown_outcome(self) -> None:
        """An uncertain Git object fetch is not a pre-effect no-op."""
        deploy = real_deploy
        expected = "b" * 40
        uncertain = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_admission_target_fetch_attempt",
            "expected_head": expected,
            "previous_origin_main": "a" * 40,
            "operation_resource_key": (
                "repo:/fixture/canonical:operation:runtime-deploy-origin-main-refresh"
            ),
            "status": "outcome_unknown",
            "effect_may_have_started": True,
        }

        def failed_fetch(head: str, snapshot: dict, *, local_mutation_tracker: dict) -> None:
            self.assertEqual(head, expected)
            local_mutation_tracker["admission_target_fetch"] = uncertain
            raise RuntimeError("exact protected-main admission object fetch failed")

        with (
            patch.object(
                deploy, "_require_release_source_admission",
                side_effect=deploy.DeploySchedulePreEffectRefusal(
                    "release admission blocked: source ancestry is unproved"
                ),
            ),
            patch.object(
                deploy, "_protected_release_admission_target_snapshot",
                return_value={"target_object_present": False},
            ),
            patch.object(deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(deploy, "_fetch_exact_release_admission_target",
                         side_effect=failed_fetch),
            patch.object(deploy, "_fresh_public_github_main") as remote,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
        ):
            with self.assertRaises(
                deploy.DeployScheduleFailureAfterLocalMutation
            ) as raised:
                deploy._grabowski_runtime_deploy_schedule_impl(
                    expected, local_mutation_tracker={}
                )
        expected_evidence = {
            **uncertain,
            "evidence_sha256": deploy._source_identity_sha256(uncertain),
        }
        self.assertEqual(
            expected_evidence, raised.exception.local_mutation_evidence
        )
        self.assertIn("object fetch failed", str(raised.exception))
        remote.assert_not_called()
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
                patch.object(deploy, "_renew_origin_main_refresh_resources",
                             return_value={"leases": []}, create=True) as renew,
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
            patch.object(deploy, "_renew_origin_main_refresh_resources",
                         return_value={"leases": []}, create=True) as renew,
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

    def test_failed_fetch_retains_digest_bound_uncertainty_in_captain_receipt(self) -> None:
        """A started-but-failed object import is not a success or contextless unknown."""
        expected = "b" * 40
        material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_admission_target_fetch_attempt",
            "expected_head": expected,
            "previous_origin_main": "c" * 40,
            "operation_resource_key":
                "repo:/home/alex/repos/grabowski:operation:runtime-deploy-origin-main-refresh",
            "status": "outcome_unknown",
            "effect_may_have_started": True,
        }
        evidence = {**material, "evidence_sha256": grips.sha256_json(material)}
        self.assertEqual(
            evidence, real_deploy._tracked_runtime_deploy_local_mutation_evidence(
                {"admission_target_fetch": material}
            ),
        )
        self.assertTrue(grips._runtime_deploy_local_mutation_uncertainty_evidence_valid(
            evidence, expected_head=expected, expected_job_prefix="grabowski-job-"
        ))
        self.assertFalse(grips._runtime_deploy_local_mutation_evidence_valid(
            evidence, expected_head=expected, expected_job_prefix="grabowski-job-"
        ))
        error = RuntimeError("Git fetch outcome unknown")
        error.local_mutation_evidence = evidence
        action = {"target": {
            "adapter": "grabowski-self", "service": "grabowski-mcp",
            "runtime_target": "heim-pc",
        }}
        with (
            patch.object(grips, "_runtime_deploy_expected_head", return_value=expected),
            patch.object(grips, "_runtime_deploy_delay_seconds", return_value=8),
            patch.object(grips, "_runtime_deploy_source_parameters", return_value=(None, None)),
            patch.object(grips, "_captain_runtime_deploy_target_errors", return_value=[]),
            patch.object(grips, "_runtime_deploy_self_preflight",
                         return_value={"ready": True, "job_prefix": "grabowski-job-"}),
            patch.object(grips, "_runtime_deploy_self_schedule", side_effect=error),
            patch.object(real_deploy, "_require_release_source_admission",
                         return_value={"independent_review_required": False}),
        ):
            result = grips._run_captain_runtime_deploy(action, {})
        self.assertTrue(result["mutation_outcome_unknown"])
        self.assertTrue(result["local_mutation_outcome_unknown"])
        self.assertFalse(result["local_mutation_observed"])
        self.assertEqual(evidence, result["local_mutation_uncertainty_evidence"])
        self.assertFalse(result["verification_passed"])
        invalid = {**evidence, "evidence_sha256": "0" * 64}
        self.assertFalse(grips._runtime_deploy_local_mutation_uncertainty_evidence_valid(
            invalid, expected_head=expected, expected_job_prefix="grabowski-job-"
        ))

        for changed in (
            {"status": "completed"},
            {"effect_may_have_started": False},
            {"previous_origin_main": "invalid"},
            {"operation_resource_key": "path:/unscoped"},
            {"expected_head": "d" * 40},
            {"schema_version": True},
            {"kind": "different-outcome-kind"},
            {"unexpected": "field"},
        ):
            material_bad = {**material, **changed}
            alleged = {
                **material_bad,
                "evidence_sha256": grips.sha256_json(material_bad),
            }
            with self.subTest(changed=changed):
                self.assertFalse(
                    grips._runtime_deploy_local_mutation_uncertainty_evidence_valid(
                        alleged,
                        expected_head=expected,
                        expected_job_prefix="grabowski-job-",
                    )
                )

        denied = grips.RuntimeDeployPreEffectRefusal(
            "ref refresh refused after uncertain fetch",
            local_mutation_evidence=evidence,
        )
        with (
            patch.object(grips, "_runtime_deploy_expected_head", return_value=expected),
            patch.object(grips, "_runtime_deploy_delay_seconds", return_value=8),
            patch.object(grips, "_runtime_deploy_source_parameters", return_value=(None, None)),
            patch.object(grips, "_captain_runtime_deploy_target_errors", return_value=[]),
            patch.object(grips, "_runtime_deploy_self_preflight",
                         return_value={"ready": True, "job_prefix": "grabowski-job-"}),
            patch.object(grips, "_runtime_deploy_self_schedule", side_effect=denied),
            patch.object(real_deploy, "_require_release_source_admission",
                         return_value={"independent_review_required": False}),
        ):
            typed = grips._run_captain_runtime_deploy(action, {})
        self.assertTrue(typed["pre_effect_refusal"])
        self.assertTrue(typed["local_mutation_outcome_unknown"])
        self.assertTrue(typed["mutation_outcome_unknown"])
        self.assertFalse(typed["local_mutation_observed"])
        self.assertEqual(evidence, typed["local_mutation_uncertainty_evidence"])

    def test_captain_admission_only_passes_explicit_bound_document_or_serving_proof(self) -> None:
        """A helper's arbitrary success-shaped return is never R3 authority."""
        deploy = real_deploy
        head = "b" * 40
        serving = "a" * 40
        valid_docs = {
            "status": "non-runtime-documentation",
            "serving_repo_head": serving,
            "target_repo_head": head,
            "changed_path_count": 1,
            "independent_review_required": False,
        }
        valid_serving = {
            "status": "already-serving-exact-source",
            "serving_repo_head": head,
            "target_repo_head": head,
            "independent_review_required": False,
        }
        cases = [
            ("valid-docs", valid_docs, True),
            ("valid-serving", valid_serving, True),
            ("empty", {}, False),
            ("unknown-status", {**valid_docs, "status": "provisional"}, False),
            ("required-r3", {**valid_docs, "independent_review_required": True}, False),
            ("missing-review-flag", {k:v for k,v in valid_docs.items()
                                     if k != "independent_review_required"}, False),
            ("target-spoof", {**valid_docs, "target_repo_head": "c"*40}, False),
            ("invalid-count", {**valid_docs, "changed_path_count": True}, False),
            ("not-same-serving", {**valid_serving, "serving_repo_head": serving}, False),
            ("non-object", ["unexpected"], False),
        ]
        for label, returned, permitted in cases:
            with (
                self.subTest(case=label),
                patch.object(deploy, "_require_release_source_admission",
                             return_value=returned),
            ):
                gate = grips._captain_independent_review_gate(
                    {"expected_head": head}, [{"action": "runtime-deploy"}],
                )
            self.assertEqual("pass" if permitted else "blocked", gate["status"])
            if permitted:
                self.assertIs(gate["details"]["required"], False)

    def test_captain_release_admission_unexpected_exception_fails_closed(self) -> None:
        deploy = real_deploy
        for error in (ImportError("provider unavailable"),
                      AttributeError("source identity missing"),
                      KeyError("required field missing")):
            with (
                self.subTest(exception=type(error).__name__),
                patch.object(deploy, "_require_release_source_admission",
                             side_effect=error),
                patch.object(deploy.privileged, "ensure_rootbroker_authority") as broker,
            ):
                gate = grips._captain_independent_review_gate(
                    {"expected_head": "b"*40}, [{"action": "runtime-deploy"}],
                )
            self.assertEqual("blocked", gate["status"])
            broker.assert_not_called()

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
        admission.assert_called_once_with("b" * 40, release_review_pr=None, captain_preview=True)





    def test_captain_missing_target_cannot_pass_review_or_launch_any_effect(self) -> None:
        """Missing ancestry is not a provisional R3/Rootbroker authorization."""
        deploy = real_deploy
        expected = "b" * 40
        denied = deploy.DeploySchedulePreEffectRefusal(
            "release admission blocked: source ancestry is unproved"
        )
        with (
            patch.object(deploy, "_require_release_source_admission", side_effect=denied) as admit,
            patch.object(deploy, "_git_result") as git_read,
            patch.object(deploy, "_canonical_main_refresh_candidate") as porcelain,
            patch.object(deploy, "_fresh_public_github_main") as public,
            patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
            patch.object(deploy.privileged, "ensure_rootbroker_authority") as rootbroker,
        ):
            gate = grips._captain_independent_review_gate(
                {"expected_head": expected}, [{"action": "runtime-deploy"}],
            )
        self.assertEqual("blocked", gate["status"])
        self.assertIn("source ancestry", str(gate.get("details")))
        admit.assert_called_once_with(expected, release_review_pr=None, captain_preview=True)
        git_read.assert_not_called()
        porcelain.assert_not_called()
        public.assert_not_called()
        fetch.assert_not_called()
        rootbroker.assert_not_called()

    def test_captain_missing_target_rejects_even_ambiguous_plumbing_or_public_main(self) -> None:
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
                patch.object(deploy, "_git_result", return_value=result) as git_read,
                patch.object(deploy, "_canonical_main_refresh_candidate") as porcelain,
                patch.object(deploy, "_fresh_public_github_main", return_value=remote) as public,
                patch.object(deploy, "_fetch_exact_release_admission_target") as fetch,
            ):
                gate = grips._captain_independent_review_gate(
                    {"expected_head": expected}, [{"action": "runtime-deploy"}],
                )
            self.assertEqual("blocked", gate["status"])
            porcelain.assert_not_called()
            fetch.assert_not_called()
            git_read.assert_not_called()
            public.assert_not_called()

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
            with self.assertRaisesRegex(RuntimeError, "ancestor check failed"):
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
                    self._git_success(self._raw_change('docs/../src/grabowski_agent_role.py')),
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
                    self._git_success(self._raw_change('docs/<REDACTED>')),
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
                    self._git_success(self._raw_change('docs/run_deploy.sh')),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "release review admission missing"):
                deploy._require_release_source_admission("b" * 40)



class CaptainAcceptedActionOriginRegressionTests(unittest.TestCase):
    """R3 evidence does not mint an accepted server-side Captain action."""

    def test_valid_r3_alone_cannot_mint_captain_release_scope(self) -> None:
        reviewed = {
            "independent_review_required": True,
            "serving_head": "a" * 40,
            "serving_release_id": "serving-release",
            "release_review_identity_sha256": "f" * 64,
            "target_head": "b" * 40,
            "status": "authenticated-post-merge-r3-ci",
        }
        with patch.object(
            real_deploy, "_require_release_source_admission", return_value=reviewed
        ):
            with self.assertRaises(real_deploy.DeploySchedulePreEffectRefusal):
                with real_deploy._captain_release_scope("b" * 40, 1460):
                    pass

    def test_direct_runtime_executor_cannot_schedule_with_r3_but_no_captain_action(self) -> None:
        reviewed = {
            "independent_review_required": True,
            "serving_head": "a" * 40,
            "serving_release_id": "serving-release",
            "release_review_identity_sha256": "f" * 64,
            "target_head": "b" * 40,
            "status": "authenticated-post-merge-r3-ci",
        }
        action = {
            "action": "runtime-deploy",
            "target": {"adapter": "grabowski-self", "service": "grabowski-mcp",
                       "runtime_target": "heim-pc"},
        }
        with (
            patch.object(grips, "_runtime_deploy_expected_head", return_value="b" * 40),
            patch.object(grips, "_runtime_deploy_delay_seconds", return_value=8),
            patch.object(grips, "_runtime_deploy_source_parameters", return_value=(None, None)),
            patch.object(grips, "_captain_runtime_deploy_target_errors", return_value=[]),
            patch.object(grips, "_runtime_deploy_self_preflight", return_value={
                "ready": True, "job_prefix": "grabowski-job-"
            }),
            patch.object(real_deploy, "_require_release_source_admission", return_value=reviewed),
            patch.object(grips, "_runtime_deploy_self_schedule", return_value={
                "unit": "grabowski-job-test"
            }) as schedule,
        ):
            result = grips._run_captain_runtime_deploy(
                action, {"release_review_pr": 1460}
            )
        schedule.assert_not_called()
        self.assertFalse(result.get("deployment_scheduled", False))



class CaptainPositiveActionOriginTests(unittest.TestCase):
    """An actual accepted Captain path issues one non-replayable action origin."""

    def test_generic_server_actor_cannot_self_issue_captain_dispatch_ticket(self) -> None:
        actor = grips.grabowski_merge_guard.issue_server_runtime_actor_identity(
            object(), profile="trusted-owner"
        )
        with self.assertRaisesRegex(
            real_deploy.DeploySchedulePreEffectRefusal, "ticket"
        ):
            with real_deploy._accepted_captain_runtime_action(
                "b" * 40, 1460,
                server_actor_identity=actor,
                execution_intent_sha256="1" * 64,
                accepted_dispatch_ticket=object(),
            ):
                self.fail("an unissued ticket must not authorize release")

    def test_accepted_captain_run_enables_exactly_one_critical_scope(self) -> None:
        expected_head = "b" * 40
        action = {"action": "runtime-deploy", "target": {
            "service": "grabowski-mcp", "runtime_target": "heim-pc",
            "adapter": "grabowski-self",
        }}
        raw_delta = (
            ":100644 100644 " + "a" * 40 + " " + "b" * 40
            + " M\x00src/grabowski_self_deploy.py\x00"
        )

        def observed_git(_repo: Path, *argv: str, **_kwargs: object) -> dict:
            if argv[0] == "merge-base":
                value = ""
            elif argv[0] == "diff":
                value = raw_delta
            elif argv[0] == "rev-parse":
                value = ("c" * 40 if argv[1].startswith("a" * 40) else "d" * 40) + "\n"
            else:
                self.fail(f"unexpected release Git read: {argv!r}")
            return {
                "returncode": 0, "timed_out": False,
                "stdout_truncated": False, "stderr_truncated": False,
                "stdout": value, "stderr": "",
            }
        params = {
            "allow_execution": True,
            "release_review_pr": 1460,
        }

        schedule = {
            "delay_seconds": 8,
            "unit": "grabowski-job-captainfixture",
            "already_scheduled": False,
            "status_tool": "grabowski_job_status",
            "logs_tool": "grabowski_job_logs",
        }
        source_readback = {"source_identity_sha256": "c" * 64}
        observed_effects: list[tuple[object, ...]] = []

        def guarded_schedule(*arguments: object) -> dict[str, object]:
            active = real_deploy._CAPTAIN_RUNTIME_RELEASE_SCOPE.get()
            self.assertTrue(real_deploy._active_captain_origin_valid(
                active, expected_head
            ))
            self.assertEqual(active["review_pr"], 1460)
            self.assertFalse(real_deploy._active_captain_origin_valid(
                {**active, "review_pr": 1461}, expected_head
            ))
            self.assertFalse(real_deploy._active_captain_origin_valid(
                {**active, "execution_intent_sha256": "2" * 64}, expected_head
            ))
            other_actor = grips.grabowski_merge_guard.issue_server_runtime_actor_identity(
                object(), profile="trusted-owner"
            )
            self.assertFalse(real_deploy._active_captain_origin_valid(
                {**active, "server_actor_identity": other_actor}, expected_head
            ))
            self.assertFalse(real_deploy._active_captain_origin_valid(
                {**active, "accepted_action_marker": object()}, expected_head
            ))
            # The MCP→Captain-dispatched path revalidates actual source-diff
            # admission, including the real release identity calculation.
            admitted = real_deploy._require_release_source_admission(expected_head)
            self.assertEqual("authenticated-post-merge-r3-ci", admitted["status"])
            self.assertEqual(
                active["identity_sha256"], admitted["release_review_identity_sha256"]
            )
            from contextvars import copy_context
            copied = copy_context()
            real_deploy._claim_captain_schedule_effect(expected_head, admitted)
            with self.assertRaises(real_deploy.DeploySchedulePreEffectRefusal):
                copied.run(
                    real_deploy._claim_captain_schedule_effect,
                    expected_head, admitted,
                )
            observed_effects.append(arguments)
            return schedule

        def authorized_dispatch(*_args: object) -> dict[str, str]:
            # Execute the *real* Captain source-scheduler gate. Only the
            # terminal source effect is replaced by a no-op test fixture.
            with (
                patch.object(grips, "_runtime_deploy_delay_seconds", return_value=8),
                patch.object(grips, "_runtime_deploy_source_parameters",
                             return_value=(None, None)),
                patch.object(grips, "_captain_runtime_deploy_target_errors",
                             return_value=[]),
                patch.object(grips, "_runtime_deploy_self_preflight",
                             return_value={
                                 "job_prefix": "grabowski-job-",
                                 "job_root": "/tmp/captain-fixture-jobs",
                                 "ready": True,
                             }),
                patch.object(grips, "_runtime_deploy_self_schedule",
                             side_effect=guarded_schedule),
                patch.object(grips, "_runtime_deploy_self_schedule_source_preflight",
                             return_value=source_readback),
                patch.object(grips, "_runtime_deploy_self_expected_argv_sha256",
                             return_value="f" * 64),
                patch.object(grips, "_runtime_deploy_schedule_errors",
                             return_value=[]),
            ):
                verified = grips._run_captain_runtime_deploy(action, params)
            self.assertTrue(verified["verification_passed"])
            self.assertTrue(verified["deployment_scheduled"])
            self.assertTrue(verified["new_job_registered"])
            self.assertEqual(observed_effects, [(expected_head, 8)])
            with self.assertRaises(real_deploy.DeploySchedulePreEffectRefusal):
                with real_deploy._captain_release_scope(expected_head, 1460):
                    pass
            return {"receipt_status": "passed"}

        mcp_server = real_deploy.base

        def run_from_mcp(name, admitted_params, **kwargs):
            self.assertEqual(name, "captain-run")
            self.assertTrue(kwargs["allow_mutation"])
            self.assertTrue(grips._server_captain_dispatch_admitted(admitted_params))
            return grips._run_captain_run(
                Mock(), admitted_params, {}, Mock(), Mock()
            )

        with (
            patch.object(mcp_server, "_require_mutations_enabled"),
            patch.object(mcp_server, "_session_grip_policy_decision", return_value={
                "allowed": True,
                "session_profile": {"profile": "trusted-owner"},
            }),
            patch.object(mcp_server, "_captain_audit_intent", return_value={
                "audit_chain_valid": True, "audit_record_sha256": "e" * 64,
            }),
            patch.object(mcp_server, "_captain_audit_completion", return_value={
                "audit_chain_valid": True, "audit_record_sha256": "d" * 64,
            }),
            patch.object(real_deploy.base, "_deployment_metadata", return_value={
                "completion_status": "complete",
                "runtime_binding_valid": True,
                "artifact_integrity_valid": True,
                "provenance_valid": True,
                "repo_head": "a" * 40,
                "release_id": "serving-release",
            }),
            patch.object(real_deploy.serving_process, "identity", return_value={
                "matches_deployed_manifest": True,
                "process_repo_head": "a" * 40,
                "process_release_id": "serving-release",
            }),
            patch.object(real_deploy, "_git_result", side_effect=observed_git
                         ) as real_git_reads,
            patch.object(
                release_admission, "validate_independent_release_review",
                return_value={
                    "review_pr": 1460, "independent_pass_count": 1,
                    "admissible_slots": ["grok-r3"],
                    "review_binding_sha256": "3" * 64,
                    "review_attempts_sha256": "4" * 64,
                },
            ) as real_r3_read,
            patch.object(
                release_admission, "_fresh_github_checks",
                return_value={
                    "checks": [{"name": "validate (3.10)", "id": 101},
                               {"name": "validate (3.12)", "id": 102}],
                    "workflow": {"id": 301891383, "path": ".github/workflows/validate.yml",
                                 "head_sha": expected_head},
                    "checks_sha256": "5" * 64,
                },
            ) as real_ci_read,
            patch.object(grips, "_captain_actions", return_value=[action]),
            patch.object(grips, "_captain_authority_gates", return_value=(
                [{"id": "test", "status": "pass", "reason": "test fixture"}], {}
            )),
            patch.object(grips, "_captain_execution_intent_review",
                         return_value=({"intent_sha256": "1" * 64}, [])),
            patch.object(grips, "_runtime_deploy_expected_head",
                         return_value=expected_head),
            patch.object(grips.grabowski_grip_orchestration,
                         "run_captain_run", side_effect=authorized_dispatch),
            patch.object(grips, "grip_run", side_effect=run_from_mcp),
        ):
            result = mcp_server._grip_run_core(
                "captain-run", params, profile="captain",
                allow_mutation=True,
                ctx=types.SimpleNamespace(session=object()),
            )
        self.assertEqual(result["receipt_status"], "passed")
        self.assertGreaterEqual(real_r3_read.call_count, 2)
        self.assertGreaterEqual(real_ci_read.call_count, 2)
        self.assertTrue(any(call.args[1] == "diff" for call in real_git_reads.call_args_list))
        self.assertFalse(grips._CAPTAIN_MCP_INGRESS_TICKETS)
        self.assertFalse(grips._CAPTAIN_ACCEPTED_RUNTIME_TICKETS)
        self.assertIsNone(real_deploy._CAPTAIN_ACCEPTED_ACTION.get())
        self.assertIsNone(real_deploy._CAPTAIN_RUNTIME_RELEASE_SCOPE.get())

    def test_direct_captain_run_with_r3_but_no_mcp_origin_cannot_dispatch(self) -> None:
        expected_head = "b" * 40
        actor = grips.grabowski_merge_guard.issue_server_runtime_actor_identity(
            object(), profile="trusted-owner"
        )
        params = {
            "allow_execution": True,
            "release_review_pr": 1460,
            "_server_runtime_actor_identity": actor,
        }
        action = {"action": "runtime-deploy", "target": {
            "adapter": "grabowski-self", "service": "grabowski-mcp",
            "runtime_target": "heim-pc",
        }}

        def no_authority(*_args: object) -> dict[str, str]:
            with self.assertRaises(real_deploy.DeploySchedulePreEffectRefusal):
                with real_deploy._captain_release_scope(expected_head, 1460):
                    pass
            return {"receipt_status": "blocked"}

        with (
            patch.object(grips, "_captain_actions", return_value=[action]),
            patch.object(grips, "_captain_authority_gates", return_value=(
                [{"id": "test", "status": "pass", "reason": "synthetic"}], {}
            )),
            patch.object(grips, "_captain_execution_intent_review",
                         return_value=({"intent_sha256": "1" * 64}, [])),
            patch.object(grips, "_runtime_deploy_expected_head",
                         return_value=expected_head),
            patch.object(grips.grabowski_grip_orchestration, "run_captain_run",
                         side_effect=no_authority),
        ):
            result = grips._run_captain_run(Mock(), params, {}, Mock(), Mock())
        self.assertEqual(result["receipt_status"], "blocked")
        self.assertFalse(grips._CAPTAIN_ACCEPTED_RUNTIME_TICKETS)
        self.assertIsNone(real_deploy._CAPTAIN_ACCEPTED_ACTION.get())

    def test_blocked_captain_action_cannot_issue_release_ticket(self) -> None:
        actor = grips.grabowski_merge_guard.issue_server_runtime_actor_identity(
            object(), profile="trusted-owner"
        )
        params = {
            "allow_execution": True,
            "release_review_pr": 1460,
            "_server_runtime_actor_identity": actor,
        }
        action = {"action": "runtime-deploy", "target": {
            "service": "grabowski-mcp", "runtime_target": "heim-pc",
            "adapter": "grabowski-self",
        }}
        with (
            patch.object(grips, "_captain_actions", return_value=[action]),
            patch.object(grips, "_captain_authority_gates", return_value=(
                [{"id": "test", "status": "blocked", "reason": "missing R3"}], {}
            )),
            patch.object(grips.grabowski_grip_orchestration, "run_captain_run",
                         return_value={"receipt_status": "blocked"}),
        ):
            result = grips._run_captain_run(Mock(), params, {}, Mock(), Mock())
        self.assertEqual(result["receipt_status"], "blocked")
        self.assertFalse(grips._CAPTAIN_ACCEPTED_RUNTIME_TICKETS)
        self.assertIsNone(real_deploy._CAPTAIN_ACCEPTED_ACTION.get())



class CaptainMcpIngressRegressionTests(unittest.TestCase):
    """The real MCP entrypoint, not a direct internal grip, admits Captain."""

    def _fixture(self):
        return {
            "actions": [{"action": "runtime-deploy", "high_impact": True}],
            "allow_execution": True,
            "release_review_pr": 1460,
        }

    def test_mcp_frontdoor_admits_and_revokes_exact_audited_action(self) -> None:
        mcp_server = real_deploy.base
        params = self._fixture()
        observed = []

        def capture_grip(name, parameters, **kwargs):
            self.assertEqual(name, "captain-run")
            self.assertTrue(kwargs["allow_mutation"])
            self.assertTrue(grips._server_captain_dispatch_admitted(parameters))
            self.assertIn("_server_runtime_actor_identity", parameters)
            observed.append(parameters["_server_runtime_actor_identity"]["owner_id"])
            return {"receipt": {"status": "passed"}, "output": {"receipt_status": "passed"}}

        with (
            patch.object(mcp_server, "_require_mutations_enabled"),
            patch.object(mcp_server, "_session_grip_policy_decision", return_value={
                "allowed": True,
                "session_profile": {"profile": "trusted-owner"},
            }),
            patch.object(mcp_server, "_captain_audit_intent", return_value={
                "audit_chain_valid": True, "audit_record_sha256": "a" * 64,
            }),
            patch.object(mcp_server, "_captain_audit_completion", return_value={
                "audit_chain_valid": True, "audit_record_sha256": "b" * 64,
            }),
            patch.object(grips, "grip_run", side_effect=capture_grip),
        ):
            result = mcp_server._grip_run_core(
                "captain-run", params, profile="captain",
                allow_mutation=True,
                ctx=types.SimpleNamespace(session=object()),
            )
        self.assertEqual(result["receipt"]["status"], "passed")
        self.assertEqual(len(observed), 1)
        self.assertFalse(grips._server_captain_dispatch_admitted(params))
        self.assertIsNone(grips._SERVER_CAPTAIN_INGRESS.get())

    def test_cloned_authenticated_mcp_ingress_cannot_mint_second_captain_origin(self) -> None:
        """One accepted frontdoor action issues at most one runtime origin."""
        from contextvars import copy_context

        mcp_server = real_deploy.base
        params = self._fixture()
        head = "b" * 40
        seen: list[bool] = []

        def observed_captain(_mod, _spec, admitted, *_args):
            seen.append(real_deploy._accepted_captain_origin_matches(
                head, admitted["release_review_pr"]
            ))
            return {"receipt_status": "passed"}

        def dispatch_from_mcp(name, admitted, **kwargs):
            self.assertEqual("captain-run", name)
            self.assertTrue(kwargs["allow_mutation"])
            cloned = copy_context()
            grips._run_captain_run(Mock(), admitted, {}, Mock(), Mock())
            cloned.run(grips._run_captain_run, Mock(), admitted, {}, Mock(), Mock())
            return {"receipt": {"status": "passed"},
                    "output": {"receipt_status": "passed"}}

        action = {"action": "runtime-deploy", "target": {
            "adapter": "grabowski-self", "service": "grabowski-mcp",
            "runtime_target": "heim-pc",
        }}
        with (
            patch.object(mcp_server, "_require_mutations_enabled"),
            patch.object(mcp_server, "_session_grip_policy_decision", return_value={
                "allowed": True, "session_profile": {"profile": "trusted-owner"},
            }),
            patch.object(mcp_server, "_captain_audit_intent", return_value={
                "audit_chain_valid": True, "audit_record_sha256": "a" * 64,
            }),
            patch.object(mcp_server, "_captain_audit_completion", return_value={
                "audit_chain_valid": True, "audit_record_sha256": "b" * 64,
            }),
            patch.object(grips, "_captain_actions", return_value=[action]),
            patch.object(grips, "_captain_authority_gates", return_value=(
                [{"id": "test", "status": "pass"}], {}
            )),
            patch.object(grips, "_captain_execution_intent_review",
                         return_value=({"intent_sha256": "1" * 64}, [])),
            patch.object(grips, "_runtime_deploy_expected_head", return_value=head),
            patch.object(grips.grabowski_grip_orchestration,
                         "run_captain_run", side_effect=observed_captain),
            patch.object(grips, "grip_run", side_effect=dispatch_from_mcp),
        ):
            mcp_server._grip_run_core(
                "captain-run", params, profile="captain", allow_mutation=True,
                ctx=types.SimpleNamespace(session=object()),
            )
        self.assertEqual([True, False], seen)
        self.assertFalse(grips._CAPTAIN_ACCEPTED_RUNTIME_TICKETS)
        self.assertFalse(grips._SERVER_CAPTAIN_INGRESS_ACTIVE)

    def test_forged_audit_and_generic_actor_cannot_mint_server_captain_origin(self) -> None:
        actor = grips.grabowski_merge_guard.issue_server_runtime_actor_identity(
            object(), profile="trusted-owner"
        )
        parameters = {
            **self._fixture(),
            "_server_runtime_actor_identity": actor,
        }
        forged_audit = {
            "audit_chain_valid": True,
            "audit_record_sha256": "e" * 64,
        }
        with self.assertRaises(grips.GripPreflightError):
            with grips._server_captain_dispatch_scope(
                parameters, actor, forged_audit
            ):
                self.fail("syntactically valid fake audit is not Captain authority")
        self.assertFalse(grips._server_captain_dispatch_admitted(parameters))
        self.assertIsNone(grips._SERVER_CAPTAIN_INGRESS.get())

    def test_missing_session_never_dispatches_captain_grip(self) -> None:
        mcp_server = real_deploy.base
        params = self._fixture()
        with (
            patch.object(mcp_server, "_require_mutations_enabled"),
            patch.object(mcp_server, "_session_grip_policy_decision", return_value={
                "allowed": True, "session_profile": {"profile": "trusted-owner"},
            }),
            patch.object(grips, "grip_run") as run,
        ):
            result = mcp_server._grip_run_core(
                "captain-run", params, profile="captain",
                allow_mutation=True, ctx=None,
            )
        self.assertEqual(result["status"], "blocked")
        run.assert_not_called()

    def test_invalid_server_intent_audit_cannot_dispatch(self) -> None:
        mcp_server = real_deploy.base
        params = self._fixture()
        with (
            patch.object(mcp_server, "_require_mutations_enabled"),
            patch.object(mcp_server, "_session_grip_policy_decision", return_value={
                "allowed": True, "session_profile": {"profile": "trusted-owner"},
            }),
            patch.object(mcp_server, "_captain_audit_intent", return_value={
                "audit_chain_valid": False,
                "audit_record_sha256": "a" * 64,
            }),
            patch.object(grips, "grip_run") as run,
        ):
            with self.assertRaises(grips.GripPreflightError):
                mcp_server._grip_run_core(
                    "captain-run", params, profile="captain",
                    allow_mutation=True,
                    ctx=types.SimpleNamespace(session=object()),
                )
        run.assert_not_called()
        self.assertIsNone(grips._SERVER_CAPTAIN_INGRESS.get())




class CaptainEffectClaimRegressionTests(unittest.TestCase):
    """An accepted Captain action is single-use even in cloned contexts."""

    def test_critical_effect_claim_is_single_use_in_cloned_context(self) -> None:
        from contextvars import copy_context

        head = "b" * 40
        review = {"independent_review_required": True,
                  "serving_head": "a" * 40,
                  "serving_release_id": "serving-release",
                  "release_review_identity_sha256": "f" * 64}
        actor = grips.grabowski_merge_guard.issue_server_runtime_actor_identity(
            object(), profile="trusted-owner"
        )
        ticket = object()
        grips._CAPTAIN_ACCEPTED_RUNTIME_TICKETS[ticket] = (head, 1460, "1" * 64)
        with patch.object(real_deploy, "_require_release_source_admission",
                          return_value=review):
            with real_deploy._accepted_captain_runtime_action(
                head, 1460, server_actor_identity=actor,
                execution_intent_sha256="1" * 64, accepted_dispatch_ticket=ticket,
            ):
                with real_deploy._captain_release_scope(head, 1460):
                    clone = copy_context()
                    bound = real_deploy._CAPTAIN_RUNTIME_RELEASE_SCOPE.get()
                    self.assertTrue(real_deploy._active_captain_origin_valid(bound, head))
                    # Repeated read-only admission before effect is legitimate.
                    real_deploy._require_release_source_admission(head)
                    real_deploy._require_release_source_admission(head)
                    self.assertTrue(real_deploy._active_captain_origin_valid(bound, head))
                    real_deploy._claim_captain_schedule_effect(head, review)
                    # Later read-only revalidation stays bound to the
                    # original execution; a second effect claim does not.
                    self.assertTrue(real_deploy._active_captain_origin_valid(bound, head))
                    with self.assertRaises(real_deploy.DeploySchedulePreEffectRefusal):
                        real_deploy._claim_captain_schedule_effect(head, review)
                    with self.assertRaises(real_deploy.DeploySchedulePreEffectRefusal):
                        clone.run(real_deploy._claim_captain_schedule_effect, head, review)
        with self.assertRaises(real_deploy.DeploySchedulePreEffectRefusal):
            clone.run(real_deploy._claim_captain_schedule_effect, head, review)
        self.assertIsNone(real_deploy._CAPTAIN_RUNTIME_RELEASE_SCOPE.get())
        self.assertIsNone(real_deploy._CAPTAIN_ACCEPTED_ACTION.get())

    def test_captain_scope_admission_refusal_is_definite_pre_effect(self) -> None:
        """A refused scope enter never constitutes an attempted scheduler call."""
        head = "b" * 40
        actor = grips.grabowski_merge_guard.issue_server_runtime_actor_identity(
            object(), profile="trusted-owner"
        )
        ticket = object()
        grips._CAPTAIN_ACCEPTED_RUNTIME_TICKETS[ticket] = (head, 1460, "1" * 64)
        action = {"action": "runtime-deploy", "target": {
            "adapter": "grabowski-self", "service": "grabowski-mcp",
            "runtime_target": "heim-pc",
        }}
        with (
            real_deploy._accepted_captain_runtime_action(
                head, 1460, server_actor_identity=actor,
                execution_intent_sha256="1" * 64, accepted_dispatch_ticket=ticket,
            ),
            patch.object(grips, "_runtime_deploy_expected_head", return_value=head),
            patch.object(grips, "_runtime_deploy_delay_seconds", return_value=8),
            patch.object(grips, "_runtime_deploy_source_parameters",
                         return_value=(None, None)),
            patch.object(grips, "_captain_runtime_deploy_target_errors",
                         return_value=[]),
            patch.object(grips, "_runtime_deploy_self_preflight",
                         return_value={"ready": True, "job_prefix": "grabowski-job-"}),
            patch.object(real_deploy, "_require_release_source_admission",
                         side_effect=real_deploy.DeploySchedulePreEffectRefusal(
                             "independent R3 missing"
                         )),
            patch.object(grips, "_runtime_deploy_self_schedule") as schedule,
        ):
            result = grips._run_captain_runtime_deploy(
                action, {"release_review_pr": 1460}
            )
        self.assertTrue(result.get("pre_effect_refusal"))
        self.assertTrue(result.get("definitely_not_scheduled"))
        self.assertFalse(result["execution_attempted"])
        self.assertFalse(result["execution_invoked"])
        self.assertFalse(result.get("mutation_outcome_unknown", False))
        schedule.assert_not_called()

    def test_final_dispatch_admission_rechecks_lease_and_source_identity(self) -> None:
        """A source/serving drift before deploy index must fail closed."""
        head = "b" * 40
        initial = {
            "status": "non-runtime-documentation",
            "target_repo_head": head,
            "serving_repo_head": "a" * 40,
            "changed_path_count": 1,
            "independent_review_required": False,
        }
        drifted = {**initial, "serving_repo_head": "c" * 40}
        source_id = {
            "canonical_repository": str(real_deploy.CANONICAL_REPOSITORY),
            "source_kind": "detached", "identity_sha256": "d" * 64,
        }
        with (
            patch.object(real_deploy, "_require_release_source_admission",
                         return_value=initial),
            patch.object(real_deploy, "_require_release_source_admission_under_lease",
                         side_effect=[initial, drifted]) as leased,
            patch.object(real_deploy, "_claim_captain_schedule_effect"),
            patch.object(real_deploy, "_deploy_schedule_lock",
                         return_value=nullcontext()),
            patch.object(real_deploy, "_fresh_public_github_main", return_value=head),
            patch.object(real_deploy, "_deployment_source_preflight", return_value=(
                Path("/tmp/pr1460-source"), Path("/bin/true"), source_id
            )),
            patch.object(real_deploy, "inflight_runtime_job_evidence",
                         return_value={"error": None, "inflight_units": []}),
            patch.object(real_deploy.privileged, "ensure_rootbroker_authority",
                         return_value={"success": True, "effect_started": False}),
            patch.object(real_deploy, "_deploy_command", return_value=["true"]),
            patch.object(real_deploy, "_matching_inflight_deploy_job",
                         return_value=None),
            patch.object(real_deploy, "_append_deploy_audit") as audit,
            patch.object(real_deploy, "_write_deploy_index") as index,
            patch.object(real_deploy.operator, "_start_job") as job,
        ):
            with self.assertRaisesRegex(
                real_deploy.DeploySchedulePreEffectRefusal, "identity drift"
            ):
                real_deploy._grabowski_runtime_deploy_schedule_impl(
                    head, delay_seconds=8, source_repository="/tmp/pr1460-source",
                    source_lease_owner_id="fixture:source", local_mutation_tracker={},
                )
        self.assertEqual(2, leased.call_count)
        audit.assert_not_called()
        index.assert_not_called()
        job.assert_not_called()

    def test_replay_refusal_precedes_public_main_and_rootbroker_effects(self) -> None:
        head = "b" * 40
        admission = {"status": "authenticated-post-merge-r3-ci",
                     "independent_review_required": True, "target_head": head}
        with (
            patch.object(real_deploy, "_require_release_source_admission",
                         return_value=admission),
            patch.object(real_deploy, "_require_release_source_admission_under_lease",
                         return_value=admission),
            patch.object(real_deploy, "_claim_captain_schedule_effect",
                         side_effect=real_deploy.DeploySchedulePreEffectRefusal(
                             "Captain action already consumed"
                         )) as claim,
            patch.object(real_deploy, "_deploy_schedule_lock", return_value=nullcontext()),
            patch.object(real_deploy, "_fresh_public_github_main") as github,
            patch.object(real_deploy, "_deployment_source_preflight") as preflight,
            patch.object(real_deploy, "_write_deploy_index") as index,
            patch.object(real_deploy.privileged, "ensure_rootbroker_authority") as rootbroker,
        ):
            with self.assertRaises(real_deploy.DeploySchedulePreEffectRefusal):
                real_deploy._grabowski_runtime_deploy_schedule_impl(
                    head, delay_seconds=8, source_repository=None,
                    source_lease_owner_id=None, ctx=None,
                    local_mutation_tracker={},
                )
        claim.assert_called_once_with(head, admission)
        github.assert_not_called()
        preflight.assert_not_called()
        index.assert_not_called()
        rootbroker.assert_not_called()

    def test_real_documentation_exemption_needs_no_claim(self) -> None:
        real_deploy._claim_captain_schedule_effect(
            "a" * 40, {"independent_review_required": False}
        )

    def test_missing_or_malformed_review_pr_blocks_before_preflight(self) -> None:
        action = {"action": "runtime-deploy", "target": {
            "adapter": "grabowski-self",
            "service": "grabowski-mcp", "runtime_target": "heim-pc",
        }}
        with (
            patch.object(grips, "_runtime_deploy_expected_head", return_value="b" * 40),
            patch.object(grips, "_runtime_deploy_delay_seconds", return_value=8),
            patch.object(grips, "_runtime_deploy_source_parameters",
                         return_value=(None, None)),
            patch.object(grips, "_captain_runtime_deploy_target_errors",
                         return_value=[]),
            patch.object(grips, "_runtime_deploy_self_preflight") as preflight,
            patch.object(grips, "_runtime_deploy_self_schedule") as schedule,
            patch.object(real_deploy, "_require_release_source_admission",
                         side_effect=real_deploy.DeploySchedulePreEffectRefusal(
                             "critical source has no R3"
                         )) as admission,
        ):
            for value in (True, False, "1460", 1460.0, -1, 0):
                with self.subTest(review_pr=value):
                    result = grips._run_captain_runtime_deploy(
                        action, {"release_review_pr": value}
                    )
                    self.assertEqual(["release_review_pr_invalid"],
                                     result["preflight_errors"])
                    self.assertFalse(result["execution_attempted"])
            result = grips._run_captain_runtime_deploy(action, {})
            self.assertTrue(result["preflight_errors"][0].startswith(
                "release_review_pr_required:"
            ))
            self.assertFalse(result["execution_attempted"])
            admission.assert_called_once_with("b" * 40, captain_preview=True)
            preflight.assert_not_called()
            schedule.assert_not_called()



if __name__ == "__main__":
    unittest.main()
