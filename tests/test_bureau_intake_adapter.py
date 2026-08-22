from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_bureau_intake as intake


class BureauIntakeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.patches = [
            mock.patch.object(intake, "ARTIFACT_ROOT", self.artifacts),
            mock.patch.object(intake.operator, "_require_operator_mutation"),
            mock.patch.object(intake, "_audit"),
            mock.patch.object(intake.base, "_append_audit"),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temp.cleanup()

    def _git_repository(self, name: str, *, origin: str) -> Path:
        repository = self.root / name
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "remote", "add", "origin", origin],
            check=True,
        )
        return repository

    def _mock_bound_launcher(self) -> mock.MagicMock:
        bound_launcher = mock.MagicMock()
        bound_launcher.return_value.__enter__.return_value = (
            17,
            "/proc/self/fd/17",
        )
        return bound_launcher

    def test_mutating_runtime_timeout_is_ambiguous_and_requires_readback(self) -> None:
        runtime = {"python_launcher": Path("/runtime/python")}
        binding = mock.Mock()
        bound_launcher = self._mock_bound_launcher()
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
            mock.patch.object(
                intake.bureau_runtime, "_assert_contract_runtime_unchanged"
            ),
            mock.patch.object(intake, "_managed_runtime_binding", return_value=binding),
            mock.patch.object(intake, "_assert_managed_runtime_unchanged"),
            mock.patch.object(intake, "_bound_launcher_fd", bound_launcher),
            mock.patch.object(
                intake.bureau_runtime, "_safe_environment", return_value={}
            ),
            mock.patch.object(
                intake.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["bureau"], 30),
            ),
        ):
            result = intake._invoke_bureau(
                ["operator-task-publish"],
                mutation=True,
                required_readback=["pull_request", "resource_leases"],
            )
        self.assertEqual(result["code"], "bureau-runtime-timeout")
        self.assertTrue(result["effect_started"])
        self.assertTrue(result["ambiguity"])
        self.assertFalse(result["retryable"])
        self.assertEqual(
            result["required_readback"], ["pull_request", "resource_leases"]
        )

    def test_preexec_drift_fails_without_effect_or_ambiguity(self) -> None:
        runtime = {"python_launcher": Path("/runtime/python")}
        binding = mock.Mock()
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
            mock.patch.object(
                intake.bureau_runtime,
                "_assert_contract_runtime_unchanged",
                side_effect=intake.bureau_runtime.BureauLeaseContractError(
                    "contract-runtime-changed-before-exec"
                ),
            ),
            mock.patch.object(intake, "_managed_runtime_binding", return_value=binding),
            mock.patch.object(intake.subprocess, "run") as run,
        ):
            result = intake._invoke_bureau(
                ["operator-task-publish"],
                mutation=True,
                required_readback=["pull_request"],
            )
        self.assertEqual(result["code"], "bureau-runtime-drift")
        self.assertFalse(result["effect_started"])
        self.assertFalse(result["ambiguity"])
        self.assertFalse(result["retryable"])
        self.assertEqual(result["required_readback"], [])
        run.assert_not_called()

    def test_read_runtime_timeout_is_retryable_without_effect_claim(self) -> None:
        runtime = {"python_launcher": Path("/runtime/python")}
        binding = mock.Mock()
        bound_launcher = self._mock_bound_launcher()
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
            mock.patch.object(
                intake.bureau_runtime, "_assert_contract_runtime_unchanged"
            ),
            mock.patch.object(intake, "_managed_runtime_binding", return_value=binding),
            mock.patch.object(intake, "_assert_managed_runtime_unchanged"),
            mock.patch.object(intake, "_bound_launcher_fd", bound_launcher),
            mock.patch.object(
                intake.bureau_runtime, "_safe_environment", return_value={}
            ),
            mock.patch.object(
                intake.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["bureau"], 30),
            ),
        ):
            result = intake._invoke_bureau(["operator-candidate-assess"])
        self.assertFalse(result["effect_started"])
        self.assertFalse(result["ambiguity"])
        self.assertTrue(result["retryable"])

    def test_non_json_command_rejection_is_typed_without_stderr_disclosure(self) -> None:
        runtime = {"python_launcher": Path("/runtime/python")}
        binding = mock.Mock()
        stderr = (
            "bureau: approval required for runtime_mutation: "
            "approval level operator is not accepted for required break_glass\n"
        )
        completed = subprocess.CompletedProcess(["bureau"], 2, "", stderr)
        bound_launcher = self._mock_bound_launcher()
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
            mock.patch.object(
                intake.bureau_runtime, "_assert_contract_runtime_unchanged"
            ),
            mock.patch.object(intake, "_managed_runtime_binding", return_value=binding),
            mock.patch.object(intake, "_assert_managed_runtime_unchanged"),
            mock.patch.object(intake, "_bound_launcher_fd", bound_launcher),
            mock.patch.object(
                intake.bureau_runtime, "_safe_environment", return_value={}
            ),
            mock.patch.object(intake.subprocess, "run", return_value=completed),
        ):
            result = intake._invoke_bureau(
                ["--json", "--json-envelope", "claim-intent"]
            )

        self.assertEqual(result["code"], "bureau-command-rejected")
        self.assertFalse(result["effect_started"])
        self.assertFalse(result["ambiguity"])
        self.assertFalse(result["retryable"])
        self.assertEqual(result["required_readback"], [])
        self.assertEqual(result["details"]["returncode"], 2)
        self.assertEqual(
            result["details"]["stdout_sha256"], hashlib.sha256(b"").hexdigest()
        )
        self.assertEqual(
            result["details"]["stderr_sha256"],
            hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        )
        self.assertNotIn(stderr.strip(), json.dumps(result))


    def test_invoke_executes_the_exact_bound_launcher_descriptor(self) -> None:
        runtime = {"python_launcher": Path("/runtime/python")}
        binding = mock.Mock()
        completed = subprocess.CompletedProcess(
            ["bureau"],
            0,
            json.dumps(
                {
                    "schema_version": 1,
                    "result": {
                        "kind": "bureau_candidate_assessment",
                        "status": "ready",
                    },
                    "runtime_identity": {
                        "compatibility": {"status": "current", "reason_codes": []}
                    },
                }
            ),
            "",
        )
        bound_launcher = self._mock_bound_launcher()
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
            mock.patch.object(
                intake.bureau_runtime, "_assert_contract_runtime_unchanged"
            ) as contract_readback,
            mock.patch.object(intake, "_managed_runtime_binding", return_value=binding),
            mock.patch.object(intake, "_assert_managed_runtime_unchanged") as readback,
            mock.patch.object(intake, "_bound_launcher_fd", bound_launcher),
            mock.patch.object(
                intake.bureau_runtime,
                "_safe_environment",
                return_value={"PATH": "/usr/bin:/bin"},
            ),
            mock.patch.object(intake.subprocess, "run", return_value=completed) as run,
        ):
            result = intake._invoke_bureau(
                ["--json", "--json-envelope", "operator-candidate-assess"],
                include_runtime_identity=True,
            )
        self.assertEqual(result["status"], "ready")
        self.assertEqual(
            result["runtime_identity"]["compatibility"]["status"], "current"
        )
        self.assertEqual(
            run.call_args.args[0],
            [
                "/runtime/python",
                "-I",
                "/proc/self/fd/17",
                "--json",
                "--json-envelope",
                "operator-candidate-assess",
            ],
        )
        self.assertEqual(run.call_args.kwargs["pass_fds"], (17,))
        self.assertEqual(
            run.call_args.kwargs["cwd"], intake.bureau_runtime.BUREAU_RUNTIME_ROOT
        )
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin"})
        self.assertEqual(contract_readback.call_count, 2)
        self.assertEqual(readback.call_count, 2)
        bound_launcher.assert_called_once_with(binding)

    def _managed_runtime_fixture(
        self,
    ) -> tuple[Path, Path, Path, Path, str, str]:
        runtime_root = self.root / ".local/share/bureau"
        snapshots_root = runtime_root / "registry-snapshots"
        registry_root = snapshots_root / "snapshot-a"
        registry_root.mkdir(parents=True)
        source_commit = "a" * 40
        tree_sha256 = "b" * 64
        inventory_path = registry_root / ".bureau-runtime-snapshot.json"
        inventory_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "bureau_registry_snapshot",
                    "source_commit": source_commit,
                    "tree_sha256": tree_sha256,
                    "paths": ["registry/queue.json"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        launcher_path = self.root / ".local/bin/bureau"
        launcher_path.parent.mkdir(parents=True)
        manifest_path = runtime_root / "deployment-manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "bureau_runtime_deployment",
                    "launcher_path": str(launcher_path),
                    "source_commit": source_commit,
                    "canonical_registry_root": str(registry_root),
                    "canonical_registry_inventory_path": str(inventory_path),
                    "canonical_registry_inventory_sha256": hashlib.sha256(
                        inventory_path.read_bytes()
                    ).hexdigest(),
                    "canonical_registry_tree_sha256": tree_sha256,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        launcher_path.write_text(
            "#!/usr/bin/env python3\n"
            "# managed-by: heimgewebe-bureau-runtime-v1\n"
            "from pathlib import Path\n"
            f"manifest_path = Path(\n    {str(manifest_path)!r}\n)\n"
            f"expected_manifest_sha256 = (\n    {manifest_sha256!r}\n)\n",
            encoding="utf-8",
        )
        launcher_path.chmod(0o700)
        return (
            runtime_root,
            launcher_path,
            manifest_path,
            inventory_path,
            source_commit,
            tree_sha256,
        )

    def _use_manifest_payload_launcher(
        self, launcher_path: Path, manifest_path: Path
    ) -> None:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload_raw = (
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        manifest["manifest_payload_sha256"] = hashlib.sha256(payload_raw).hexdigest()
        manifest_path.write_text(
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        launcher_path.write_text(
            "#!/usr/bin/env python3\n"
            "# managed-by: heimgewebe-bureau-runtime-v1\n"
            "from pathlib import Path\n"
            f"manifest_path = Path({str(manifest_path)!r})\n"
            "manifest_digest_field = 'manifest_payload_sha256'\n",
            encoding="utf-8",
        )
        launcher_path.chmod(0o700)

    def test_managed_runtime_binding_binds_atomic_snapshots(self) -> None:
        runtime_root, launcher, manifest, inventory, source_commit, tree_sha256 = (
            self._managed_runtime_fixture()
        )
        with mock.patch.object(
            intake.bureau_runtime, "BUREAU_RUNTIME_ROOT", runtime_root
        ):
            binding = intake._managed_runtime_binding()
            intake._assert_managed_runtime_unchanged(binding)
        self.assertEqual(binding.source_commit, source_commit)
        self.assertEqual(binding.registry_tree_sha256, tree_sha256)
        self.assertEqual(binding.launcher.path, launcher)
        self.assertEqual(binding.manifest.path, manifest)
        self.assertEqual(binding.inventory.path, inventory)
        self.assertEqual(
            binding.manifest.sha256,
            hashlib.sha256(binding.manifest.raw).hexdigest(),
        )
        self.assertEqual(
            binding.inventory.sha256,
            hashlib.sha256(binding.inventory.raw).hexdigest(),
        )

    def test_managed_runtime_binding_accepts_manifest_payload_launcher(self) -> None:
        runtime_root, launcher, manifest, _, source_commit, tree_sha256 = (
            self._managed_runtime_fixture()
        )
        self._use_manifest_payload_launcher(launcher, manifest)
        with mock.patch.object(
            intake.bureau_runtime, "BUREAU_RUNTIME_ROOT", runtime_root
        ):
            binding = intake._managed_runtime_binding()
            intake._assert_managed_runtime_unchanged(binding)
        self.assertEqual(binding.source_commit, source_commit)
        self.assertEqual(binding.registry_tree_sha256, tree_sha256)

    def test_managed_runtime_binding_rejects_manifest_payload_digest_drift(
        self,
    ) -> None:
        runtime_root, launcher, manifest, _, _, _ = self._managed_runtime_fixture()
        self._use_manifest_payload_launcher(launcher, manifest)
        manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
        manifest_value["installed_at"] = "drifted-after-binding"
        manifest.write_text(
            json.dumps(
                manifest_value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        with mock.patch.object(
            intake.bureau_runtime, "BUREAU_RUNTIME_ROOT", runtime_root
        ):
            with self.assertRaisesRegex(
                intake.bureau_runtime.BureauLeaseContractError,
                "manifest-payload-digest-mismatch",
            ):
                intake._managed_runtime_binding()

    def test_managed_runtime_binding_rejects_launcher_manifest_digest_drift(
        self,
    ) -> None:
        runtime_root, launcher, manifest, _, _, _ = self._managed_runtime_fixture()
        launcher.write_text(
            "#!/usr/bin/env python3\n"
            "# managed-by: heimgewebe-bureau-runtime-v1\n"
            "from pathlib import Path\n"
            f"manifest_path = Path({str(manifest)!r})\n"
            f"expected_manifest_sha256 = {'0' * 64!r}\n",
            encoding="utf-8",
        )
        launcher.chmod(0o700)
        with mock.patch.object(
            intake.bureau_runtime, "BUREAU_RUNTIME_ROOT", runtime_root
        ):
            with self.assertRaisesRegex(
                intake.bureau_runtime.BureauLeaseContractError,
                "manifest-digest-mismatch",
            ):
                intake._managed_runtime_binding()

    def test_managed_runtime_binding_rejects_dynamic_launcher_binding(self) -> None:
        runtime_root, launcher, _, _, _, _ = self._managed_runtime_fixture()
        launcher.write_text(
            "#!/usr/bin/env python3\n"
            "# managed-by: heimgewebe-bureau-runtime-v1\n"
            "from pathlib import Path\n"
            "manifest_path = Path(__import__('os').environ['MANIFEST'])\n"
            f"expected_manifest_sha256 = {'0' * 64!r}\n",
            encoding="utf-8",
        )
        launcher.chmod(0o700)
        with mock.patch.object(
            intake.bureau_runtime, "BUREAU_RUNTIME_ROOT", runtime_root
        ):
            with self.assertRaisesRegex(
                intake.bureau_runtime.BureauLeaseContractError,
                "manifest-path-binding-invalid",
            ):
                intake._managed_runtime_binding()

    def test_managed_runtime_binding_reports_missing_inventory_precisely(self) -> None:
        runtime_root, _, _, inventory, _, _ = self._managed_runtime_fixture()
        inventory.unlink()
        with mock.patch.object(
            intake.bureau_runtime, "BUREAU_RUNTIME_ROOT", runtime_root
        ):
            with self.assertRaisesRegex(
                intake.bureau_runtime.BureauLeaseContractError,
                "canonical-registry-inventory-unavailable",
            ):
                intake._managed_runtime_binding()

    def test_snapshot_readback_detects_identity_or_content_drift(self) -> None:
        path = self.root / "binding.json"
        path.write_text('{"value":1}\n', encoding="utf-8")
        snapshot = intake._read_regular_file_snapshot(path, label="test-binding")
        path.write_text('{"value":2}\n', encoding="utf-8")
        with self.assertRaisesRegex(
            intake.bureau_runtime.BureauLeaseContractError,
            "test-binding-changed-during-call",
        ):
            intake._assert_snapshot_unchanged(snapshot, label="test-binding")

    def test_candidate_record_writes_digest_bound_private_request(self) -> None:
        request = {
            "schema_version": 1,
            "idempotency_key": "conversation:1",
            "title": "Record candidate",
            "source_kind": "conversation",
            "desired_outcome": "Create one task",
        }
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={
                "kind": "bureau_candidate_record_result",
                "status": "recorded",
            },
        ) as invoke:
            result = intake.grabowski_bureau_candidate_record(request)
        request_path = Path(invoke.call_args.args[0][-1])
        self.assertEqual(json.loads(request_path.read_text()), request)
        self.assertEqual(request_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.artifacts.stat().st_mode & 0o777, 0o700)
        self.assertEqual(result["status"], "recorded")
        self.assertEqual(request_path.stem, result["adapter_request_sha256"])

    def test_candidate_record_normalizes_exact_heimgewebe_repo_path_before_hashing(self) -> None:
        repository = self._git_repository(
            "grabowski", origin="git@github.com:heimgewebe/grabowski.git"
        )
        request = {
            "schema_version": 1,
            "idempotency_key": "conversation:repo-path:1",
            "title": "Record candidate",
            "source_kind": "conversation",
            "desired_outcome": "Create one task",
            "repo": str(repository),
        }
        expected = {**request, "repo": "repo.grabowski"}
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={
                "kind": "bureau_candidate_record_result",
                "status": "recorded",
            },
        ) as invoke:
            result = intake.grabowski_bureau_candidate_record(request)
        request_path = Path(invoke.call_args.args[0][-1])
        self.assertEqual(json.loads(request_path.read_text()), expected)
        self.assertEqual(intake._sha256(intake._canonical_json(expected)), request_path.stem)
        self.assertEqual(request_path.stem, result["adapter_request_sha256"])
        self.assertEqual(str(repository), request["repo"])

    def test_candidate_repo_path_normalization_accepts_safe_scp_ssh_username(self) -> None:
        repository = self._git_repository(
            "alternate-ssh-user",
            origin="org-236528253@github.com:heimgewebe/heim-pc.git",
        )
        self.assertEqual(
            "repo.heim-pc",
            intake._canonical_bureau_repo_resource(str(repository)),
        )
        mixed_case_repository = self._git_repository(
            "mixed-case-repo",
            origin="org-236528253@github.com:heimgewebe/semantAH.git",
        )
        self.assertEqual(
            "repo.semantah",
            intake._canonical_bureau_repo_resource(str(mixed_case_repository)),
        )

    def test_candidate_repo_identity_normalizes_exact_heimgewebe_owner_slug(self) -> None:
        self.assertEqual(
            "repo.bureau",
            intake._canonical_bureau_repo_resource("heimgewebe/bureau"),
        )
        self.assertEqual(
            {"repo": "repo.bureau"},
            intake._normalize_candidate_request({"repo": "heimgewebe/bureau"}),
        )
        self.assertEqual(
            "repo.semantah",
            intake._canonical_bureau_repo_resource("heimgewebe/semantAH"),
        )
        for value in (
            "other/bureau",
            "heimgewebe/bureau/extra",
            "heimgewebe/",
        ):
            self.assertIsNone(intake._canonical_bureau_repo_resource(value))

    def test_candidate_repo_path_normalization_fails_closed_for_untrusted_shapes(self) -> None:
        foreign = self._git_repository(
            "foreign", origin="git@github.com:other/foreign.git"
        )
        self.assertIsNone(intake._canonical_bureau_repo_resource(str(foreign)))

        repository = self._git_repository(
            "shape-target", origin="https://github.com/heimgewebe/grabowski.git"
        )
        subdirectory = repository / "src"
        subdirectory.mkdir()
        self.assertIsNone(intake._canonical_bureau_repo_resource(str(subdirectory)))

        linked = self.root / "symlink-repo"
        linked.symlink_to(repository, target_is_directory=True)
        self.assertIsNone(intake._canonical_bureau_repo_resource(str(linked)))

    def test_candidate_repo_path_normalization_ignores_inherited_git_overrides(self) -> None:
        repository = self._git_repository(
            "override-target", origin="git@github.com:heimgewebe/grabowski.git"
        )
        other = self._git_repository(
            "override-other", origin="git@github.com:other/foreign.git"
        )
        with mock.patch.dict(
            os.environ,
            {"GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other)},
            clear=False,
        ):
            self.assertEqual(
                "repo.grabowski",
                intake._canonical_bureau_repo_resource(str(repository)),
            )

    def test_candidate_repo_path_normalization_rejects_multiple_local_origins(self) -> None:
        repository = self._git_repository(
            "multiple-origins", origin="git@github.com:heimgewebe/grabowski.git"
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "config",
                "--add",
                "remote.origin.url",
                "https://github.com/heimgewebe/audio.git",
            ],
            check=True,
        )
        self.assertIsNone(intake._canonical_bureau_repo_resource(str(repository)))

    def test_git_identity_lines_streams_oversized_origin_under_hard_byte_ceiling(self) -> None:
        repository = self._git_repository(
            "oversized-origin", origin="git@github.com:heimgewebe/grabowski.git"
        )
        oversized_origin = (
            "https://github.com/heimgewebe/"
            + "a" * (intake.CANDIDATE_REPO_IDENTITY_MAX_OUTPUT_BYTES + 4096)
            + ".git"
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "config",
                "--local",
                "remote.origin.url",
                oversized_origin,
            ],
            check=True,
        )
        observed: list[tuple[bytes, bytes, bool, bool, bool]] = []
        original = intake.base._read_limited_process_pipes

        def capture(*args: object, **kwargs: object) -> tuple[bytes, bytes, bool, bool, bool]:
            result = original(*args, **kwargs)
            observed.append(result)
            return result

        with mock.patch.object(
            intake.base, "_read_limited_process_pipes", side_effect=capture
        ):
            self.assertIsNone(
                intake._git_identity_lines(
                    repository, "config", "--local", "--get-all", "remote.origin.url"
                )
            )
        self.assertEqual(len(observed), 1)
        stdout, _stderr, timed_out, stdout_truncated, _stderr_truncated = observed[0]
        self.assertFalse(timed_out)
        self.assertTrue(stdout_truncated)
        self.assertLessEqual(
            len(stdout), intake.CANDIDATE_REPO_IDENTITY_MAX_OUTPUT_BYTES
        )

    def test_bureau_repo_resource_origin_parser_accepts_only_exact_heimgewebe_origins(self) -> None:
        self.assertEqual(
            "repo.grabowski",
            intake._bureau_repo_resource_from_origin(
                "ssh://git@github.com/heimgewebe/grabowski.git"
            ),
        )
        self.assertEqual(
            "repo.grabowski",
            intake._bureau_repo_resource_from_origin(
                "https://github.com/heimgewebe/grabowski"
            ),
        )
        self.assertEqual(
            "repo.heim-pc",
            intake._bureau_repo_resource_from_origin(
                "org-236528253@github.com:heimgewebe/heim-pc.git"
            ),
        )
        self.assertEqual(
            "repo.audio",
            intake._bureau_repo_resource_from_origin(
                "deploy.user@github.com:heimgewebe/audio.git"
            ),
        )
        for origin in (
            "-oProxyCommand@github.com:heimgewebe/grabowski.git",
            "org-236528253@github.com.evil:heimgewebe/grabowski.git",
            "org-236528253@github.com:other/grabowski.git",
            "org-236528253@github.com:heimgewebe/grabowski/extra.git",
        ):
            self.assertIsNone(intake._bureau_repo_resource_from_origin(origin))
        self.assertIsNone(
            intake._bureau_repo_resource_from_origin(
                "https://github.com/other/grabowski.git"
            )
        )
        self.assertEqual(
            "repo.grabowski",
            intake._bureau_repo_resource_from_origin(
                "https://github.com/heimgewebe/Grabowski.git"
            ),
        )
        self.assertEqual(
            {"repo": "repo.grabowski"},
            intake._normalize_candidate_request({"repo": "repo.grabowski"}),
        )

    def test_candidate_record_carries_valid_refinement_binding(self) -> None:
        request = {
            "schema_version": 1,
            "idempotency_key": "conversation:refinement:2",
            "title": "Refined candidate",
            "source_kind": "conversation",
            "desired_outcome": "Refine the existing candidate",
            "supersedes_event_id": 31,
        }
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={
                "kind": "bureau_candidate_record_result",
                "status": "recorded",
            },
        ) as invoke:
            result = intake.grabowski_bureau_candidate_record(request)
        request_path = Path(invoke.call_args.args[0][-1])
        self.assertEqual(json.loads(request_path.read_text()), request)
        self.assertEqual(result["status"], "recorded")
        self.assertEqual(request_path.stem, result["adapter_request_sha256"])

    def test_candidate_record_exposes_exact_ambiguous_readback_selector(self) -> None:
        request = {
            "schema_version": 1,
            "idempotency_key": " conversation:bounty:path-b:v1 ",
            "title": "Authorized bounty path",
            "source_kind": "conversation",
            "desired_outcome": "Create one task",
        }
        failure = {
            "schema_version": 1,
            "kind": "grabowski_bureau_intake_adapter_failure",
            "code": "bureau-command-rejected",
            "effect_started": True,
            "retryable": False,
            "ambiguity": True,
            "required_readback": ["candidate_by_idempotency_key"],
            "details": {},
        }
        with mock.patch.object(intake, "_invoke_bureau", return_value=failure):
            result = intake.grabowski_bureau_candidate_record(request)
        self.assertEqual(
            result["readback_selector"],
            {
                "kind": "idempotency_key",
                "idempotency_key": "conversation:bounty:path-b:v1",
            },
        )

    def test_candidate_record_omits_unusable_ambiguous_readback_selector(self) -> None:
        request = {
            "schema_version": 1,
            "idempotency_key": "conversation:bounty:path-b:v1",
            "title": "Authorized bounty path",
            "source_kind": "conversation",
            "desired_outcome": "Create one task",
        }
        failure = {
            "schema_version": 1,
            "kind": "grabowski_bureau_intake_adapter_failure",
            "code": "bureau-output-invalid",
            "effect_started": True,
            "retryable": False,
            "ambiguity": True,
            "required_readback": None,
            "details": {},
        }
        with mock.patch.object(intake, "_invoke_bureau", return_value=failure):
            result = intake.grabowski_bureau_candidate_record(request)
        self.assertNotIn("readback_selector", result)

    def test_candidate_assess_supports_idempotency_key_readback(self) -> None:
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={"kind": "bureau_candidate_assessment"},
        ) as invoke:
            result = intake.grabowski_bureau_candidate_assess(
                {
                    "kind": "idempotency_key",
                    "idempotency_key": "conversation:bounty:path-b:v1",
                }
            )
        self.assertEqual(result["kind"], "bureau_candidate_assessment")
        self.assertEqual(
            [
                "--json",
                "--json-envelope",
                "operator-candidate-assess",
                "--idempotency-key",
                "conversation:bounty:path-b:v1",
            ],
            invoke.call_args.args[0],
        )

    def test_candidate_record_preserves_bureau_refinement_failure(self) -> None:
        request = {
            "schema_version": 1,
            "idempotency_key": "conversation:invalid-refinement",
            "title": "Invalid refinement",
            "source_kind": "conversation",
            "desired_outcome": "Reject an invalid predecessor binding",
            "supersedes_event_id": True,
        }
        failure = {
            "schema_version": 1,
            "kind": "bureau_operator_intake_failure",
            "status": "failed",
            "code": "supersedes-event-id-invalid",
            "effect_started": False,
            "retryable": False,
            "ambiguity": False,
            "required_readback": [],
        }
        with mock.patch.object(intake, "_invoke_bureau", return_value=failure) as invoke:
            result = intake.grabowski_bureau_candidate_record(request)
        request_path = Path(invoke.call_args.args[0][-1])
        self.assertEqual(json.loads(request_path.read_text()), request)
        self.assertEqual(result["code"], "supersedes-event-id-invalid")
        self.assertFalse(result["effect_started"])
        self.assertFalse(result["ambiguity"])

    def test_candidate_assess_exposes_typed_and_legacy_compatible_selectors(self) -> None:
        signature = inspect.signature(intake.grabowski_bureau_candidate_assess)
        self.assertEqual(
            [
                "selector",
                "expected_initiative",
                "expected_task_id",
                "candidate_id",
                "event_id",
                "idempotency_key",
                "initiative",
                "task_id",
            ],
            list(signature.parameters),
        )
        self.assertIsNone(signature.parameters["selector"].default)
        with self.assertRaisesRegex(
            ValueError,
            "candidate_id, event_id or idempotency_key.*binding checks",
        ):
            intake.grabowski_bureau_candidate_assess()
        with self.assertRaisesRegex(
            ValueError,
            "initiative and task_id are binding checks",
        ):
            intake.grabowski_bureau_candidate_assess(
                initiative="INIT", task_id="INIT-T001"
            )
        with self.assertRaises(ValueError):
            intake.grabowski_bureau_candidate_assess(
                {"kind": "candidate_id", "candidate_id": 1}
            )
        with self.assertRaises(ValueError):
            intake.grabowski_bureau_candidate_assess(
                {"kind": "event_id", "event_id": 0}
            )
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={"kind": "bureau_candidate_assessment"},
        ) as invoke:
            result = intake.grabowski_bureau_candidate_assess(
                {"kind": "candidate_id", "candidate_id": "candidate-a"},
                expected_initiative="INIT",
                expected_task_id="INIT-T001",
            )
        self.assertEqual(result["kind"], "bureau_candidate_assessment")
        self.assertEqual(
            [
                "--json",
                "--json-envelope",
                "operator-candidate-assess",
                "--candidate-id",
                "candidate-a",
                "--initiative",
                "INIT",
                "--task-id",
                "INIT-T001",
            ],
            invoke.call_args.args[0],
        )

    def test_candidate_assess_registered_schema_is_additive_and_cache_safe(self) -> None:
        if not hasattr(intake.mcp, "list_tools"):
            self.skipTest("real FastMCP unavailable in dependency-free validation")
        tool = next(
            item
            for item in asyncio.run(intake.mcp.list_tools())
            if item.name == "grabowski_bureau_candidate_assess"
        )
        schema = tool.inputSchema
        self.assertEqual(
            {
                "selector",
                "expected_initiative",
                "expected_task_id",
                "candidate_id",
                "event_id",
                "idempotency_key",
                "initiative",
                "task_id",
            },
            set(schema["properties"]),
        )
        self.assertEqual(set(), set(schema.get("required", [])))
        self.assertEqual(
            {
                "#/$defs/BureauCandidateIdSelector",
                "#/$defs/BureauEventIdSelector",
                "#/$defs/BureauIdempotencyKeySelector",
            },
            {
                variant["$ref"]
                for variant in schema["properties"]["selector"]["anyOf"]
                if "$ref" in variant
            },
        )
        candidate = schema["$defs"]["BureauCandidateIdSelector"]
        event = schema["$defs"]["BureauEventIdSelector"]
        idempotency = schema["$defs"]["BureauIdempotencyKeySelector"]
        self.assertFalse(candidate["additionalProperties"])
        self.assertFalse(event["additionalProperties"])
        self.assertFalse(idempotency["additionalProperties"])
        self.assertEqual({"kind", "candidate_id"}, set(candidate["required"]))
        self.assertEqual({"kind", "event_id"}, set(event["required"]))
        self.assertEqual(
            {"kind", "idempotency_key"}, set(idempotency["required"])
        )
        self.assertEqual("candidate_id", candidate["properties"]["kind"]["const"])
        self.assertEqual("event_id", event["properties"]["kind"]["const"])
        self.assertEqual(
            "idempotency_key", idempotency["properties"]["kind"]["const"]
        )
        self.assertEqual("string", candidate["properties"]["candidate_id"]["type"])
        self.assertEqual("integer", event["properties"]["event_id"]["type"])
        self.assertEqual(
            "string", idempotency["properties"]["idempotency_key"]["type"]
        )

    def test_candidate_assess_accepts_stale_published_connector_shape(self) -> None:
        if not hasattr(intake.mcp, "_tool_manager"):
            self.skipTest("real FastMCP unavailable in dependency-free validation")
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={"kind": "bureau_candidate_assessment"},
        ) as invoke:
            result = asyncio.run(
                intake.mcp._tool_manager.call_tool(
                    "grabowski_bureau_candidate_assess",
                    {
                        "candidate_id": "candidate-a",
                        "event_id": 0,
                        "initiative": "INIT",
                        "task_id": "INIT-T001",
                    },
                )
            )
        self.assertEqual("bureau_candidate_assessment", result["kind"])
        self.assertEqual(
            [
                "--json",
                "--json-envelope",
                "operator-candidate-assess",
                "--candidate-id",
                "candidate-a",
                "--initiative",
                "INIT",
                "--task-id",
                "INIT-T001",
            ],
            invoke.call_args.args[0],
        )

    def test_candidate_assess_accepts_flat_idempotency_key_shape(self) -> None:
        if not hasattr(intake.mcp, "_tool_manager"):
            self.skipTest("real FastMCP unavailable in dependency-free validation")
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={"kind": "bureau_candidate_assessment"},
        ) as invoke:
            result = asyncio.run(
                intake.mcp._tool_manager.call_tool(
                    "grabowski_bureau_candidate_assess",
                    {
                        "candidate_id": "",
                        "event_id": 0,
                        "idempotency_key": "conversation:bounty:path-b:v1",
                        "initiative": "",
                        "task_id": "",
                    },
                )
            )
        self.assertEqual("bureau_candidate_assessment", result["kind"])
        self.assertEqual(
            [
                "--json",
                "--json-envelope",
                "operator-candidate-assess",
                "--idempotency-key",
                "conversation:bounty:path-b:v1",
            ],
            invoke.call_args.args[0],
        )

    def test_candidate_assess_legacy_event_id_is_strict_before_dispatch(self) -> None:
        if not hasattr(intake.mcp, "_tool_manager"):
            self.skipTest("real FastMCP unavailable in dependency-free validation")
        from mcp.server.fastmcp.exceptions import ToolError

        with mock.patch.object(intake, "_invoke_bureau") as invoke:
            with self.assertRaisesRegex(ToolError, "valid integer"):
                asyncio.run(
                    intake.mcp._tool_manager.call_tool(
                        "grabowski_bureau_candidate_assess",
                        {
                            "candidate_id": "",
                            "event_id": True,
                            "initiative": "",
                            "task_id": "",
                        },
                    )
                )
        invoke.assert_not_called()

    def test_candidate_assess_rejects_mixed_or_conflicting_contracts(self) -> None:
        with self.assertRaisesRegex(ValueError, "not both"):
            intake.grabowski_bureau_candidate_assess(
                {"kind": "event_id", "event_id": 31}, candidate_id="candidate-a"
            )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            intake.grabowski_bureau_candidate_assess(
                candidate_id="candidate-a",
                idempotency_key="conversation:bounty:path-b:v1",
            )
        with self.assertRaisesRegex(ValueError, "conflicting initiative binding"):
            intake.grabowski_bureau_candidate_assess(
                {"kind": "event_id", "event_id": 31},
                expected_initiative="INIT-A",
                initiative="INIT-B",
            )

    def test_candidate_assess_rejects_malformed_selector_objects(self) -> None:
        invalid = [
            "candidate-a",
            {},
            {"kind": "other", "candidate_id": "candidate-a"},
            {"kind": "candidate_id"},
            {"kind": "candidate_id", "candidate_id": ""},
            {"kind": "candidate_id", "candidate_id": "candidate\x00a"},
            {
                "kind": "candidate_id",
                "candidate_id": "candidate-a",
                "event_id": 31,
            },
            {"kind": "event_id"},
            {"kind": "event_id", "event_id": True},
            {"kind": "event_id", "event_id": "31"},
            {"kind": "event_id", "event_id": -1},
            {
                "kind": "event_id",
                "event_id": 31,
                "candidate_id": "candidate-a",
            },
            {"kind": "idempotency_key"},
            {"kind": "idempotency_key", "idempotency_key": 31},
            {"kind": "idempotency_key", "idempotency_key": ""},
            {
                "kind": "idempotency_key",
                "idempotency_key": "conversation:bounty\x00path-b",
            },
            {
                "kind": "idempotency_key",
                "idempotency_key": "conversation:bounty:path-b:v1",
                "candidate_id": "candidate-a",
            },
        ]
        for selector in invalid:
            with self.subTest(selector=selector):
                with self.assertRaises(ValueError):
                    intake.grabowski_bureau_candidate_assess(selector)

    def test_candidate_assess_routes_event_selector_without_task_guessing(self) -> None:
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={"kind": "bureau_candidate_assessment"},
        ) as invoke:
            intake.grabowski_bureau_candidate_assess(
                {"kind": "event_id", "event_id": 31}
            )
        self.assertEqual(
            [
                "--json",
                "--json-envelope",
                "operator-candidate-assess",
                "--event-id",
                "31",
            ],
            invoke.call_args.args[0],
        )

    def test_registry_defaults_use_isolated_control_checkout(self) -> None:
        expected = str(intake.bureau_runtime.BUREAU_CONTROL_ROOT)
        functions = (
            intake.grabowski_bureau_task_propose,
            intake.grabowski_bureau_task_review,
            intake.grabowski_bureau_task_publish_preview,
            intake.grabowski_bureau_task_publish,
        )
        for function in functions:
            with self.subTest(function=function.__name__):
                self.assertEqual(
                    inspect.signature(function).parameters["registry_root"].default,
                    expected,
                )

    def test_shared_workbench_registry_root_is_rejected(self) -> None:
        shared = self.root / "shared-workbench"
        control = self.root / "control"
        shared.mkdir()
        control.mkdir()
        with (
            mock.patch.object(intake.bureau_runtime, "BUREAU_REPOSITORY_ROOT", shared),
            mock.patch.object(intake.bureau_runtime, "BUREAU_CONTROL_ROOT", control),
        ):
            with self.assertRaisesRegex(
                intake.bureau_runtime.BureauLeaseContractError,
                "shared-workbench-registry-root-forbidden",
            ):
                intake._prepare_registry_root(
                    str(shared), refresh=True, mutation=True
                )

    def test_control_registry_root_refreshes_before_mutation(self) -> None:
        shared = self.root / "shared-workbench"
        control = self.root / "control"
        shared.mkdir()
        control.mkdir()
        order: list[str] = []
        with (
            mock.patch.object(intake.bureau_runtime, "BUREAU_REPOSITORY_ROOT", shared),
            mock.patch.object(intake.bureau_runtime, "BUREAU_CONTROL_ROOT", control),
            mock.patch.object(
                intake.operator,
                "_require_operator_mutation",
                side_effect=lambda *_args, **_kwargs: order.append("policy"),
            ) as policy,
            mock.patch.object(
                intake.bureau_runtime,
                "refresh_bureau_control_checkout",
                side_effect=lambda: order.append("refresh") or {"status": "current"},
            ) as refresh,
        ):
            resolved = intake._prepare_registry_root(
                str(control), refresh=True, mutation=True
            )
        self.assertEqual(resolved, str(control.resolve()))
        self.assertEqual(order, ["policy", "refresh"])
        policy.assert_called_once_with("terminal_execute", path=str(control.resolve()))
        refresh.assert_called_once_with()

    def test_task_propose_is_adapter_idempotent(self) -> None:
        task = {"schema_version": 1, "id": "INIT-T099"}

        def invoke(arguments, **_kwargs):
            if "--write-plan" in arguments:
                plan = Path(arguments[arguments.index("--write-plan") + 1])
                plan.write_text(
                    json.dumps(
                        {
                            "publishing_task_id": "INIT-T001",
                            "proposal_sha256": "a" * 64,
                        }
                    )
                    + "\n"
                )
                return {"kind": "bureau_task_proposal_result", "status": "proposed"}
            return {
                "kind": "bureau_task_publication_preview",
                "status": "ready",
                "proposal_sha256": "a" * 64,
            }

        with mock.patch.object(intake, "_invoke_bureau", side_effect=invoke) as adapter:
            first = intake.grabowski_bureau_task_propose(
                task,
                "INIT-T001",
                candidate_id="candidate-a",
                registry_root=str(self.root),
            )
            second = intake.grabowski_bureau_task_propose(
                task,
                "INIT-T001",
                candidate_id="candidate-a",
                registry_root=str(self.root),
            )
        self.assertEqual(adapter.call_count, 2)
        self.assertEqual(first["adapter_proposal_id"], second["adapter_proposal_id"])
        self.assertFalse(first["idempotent_adapter_replay"])
        self.assertTrue(second["idempotent_adapter_replay"])

    def test_task_review_binds_exact_digest_without_caller_timestamp(self) -> None:
        proposal_id = "b" * 64
        self._write_proposal(proposal_id)
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={
                "kind": "bureau_task_review_result",
                "status": "reviewed",
                "proposal_sha256": "c" * 64,
            },
        ) as invoke:
            result = intake.grabowski_bureau_task_review(
                proposal_id,
                "operator-reviewer",
                "c" * 64,
                registry_root=str(self.root),
            )
        arguments = invoke.call_args.args[0]
        self.assertIn("operator-task-review", arguments)
        self.assertEqual(arguments[arguments.index("--reviewer") + 1], "operator-reviewer")
        self.assertEqual(arguments[arguments.index("--proposal-sha256") + 1], "c" * 64)
        self.assertNotIn("--reviewed-at", arguments)
        self.assertTrue(invoke.call_args.kwargs["mutation"])
        self.assertEqual(invoke.call_args.kwargs["required_readback"], ["proposal_artifact"])
        self.assertEqual(result["adapter_proposal_id"], proposal_id)

    def test_task_review_rejects_invalid_public_inputs_before_bureau(self) -> None:
        proposal_id = "b" * 64
        self._write_proposal(proposal_id)
        with mock.patch.object(intake, "_invoke_bureau") as invoke:
            with self.assertRaises(ValueError):
                intake.grabowski_bureau_task_review(
                    proposal_id, "", "c" * 64, registry_root=str(self.root)
                )
            with self.assertRaises(ValueError):
                intake.grabowski_bureau_task_review(
                    proposal_id, "reviewer", "not-a-digest", registry_root=str(self.root)
                )
        invoke.assert_not_called()

    def test_task_review_rejects_symlink_plan(self) -> None:
        proposal_id = "a" * 64
        directory = self.artifacts / "proposals" / proposal_id
        directory.mkdir(parents=True)
        target = directory / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        (directory / "plan.json").symlink_to(target)
        with self.assertRaises(FileNotFoundError):
            intake.grabowski_bureau_task_review(
                proposal_id, "reviewer", "c" * 64, registry_root=str(self.root)
            )

    def _write_proposal(self, proposal_id: str = "b" * 64) -> Path:
        directory = self.artifacts / "proposals" / proposal_id
        directory.mkdir(parents=True)
        (directory / "plan.json").write_text(
            json.dumps(
                {
                    "publishing_task_id": "INIT-T001",
                    "proposal_sha256": "c" * 64,
                }
            )
            + "\n"
        )
        return directory

    def test_publish_acquires_exact_bound_resources_and_releases_on_success(
        self,
    ) -> None:
        proposal_id = "b" * 64
        directory = self._write_proposal(proposal_id)
        keys = [
            "path:/home/alex/repos/bureau/.bureau-scopes/registry-publication",
            "path:/home/alex/repos/bureau/registry/tasks/INIT-T099.json",
        ]
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "required_resource_keys": keys,
        }

        def invoke(arguments, **_kwargs):
            receipt = Path(arguments[arguments.index("--receipt") + 1])
            receipt.write_text(
                json.dumps({"kind": "bureau_task_publication_receipt"}) + "\n"
            )
            return {"kind": "bureau_task_publication_receipt", "status": "published"}

        acquired = {
            "expires_at_unix": 200,
            "bureau_contract": {"kind": "bureau_lease_diagnostics"},
        }
        released = {"released": [{"resource_key": key} for key in keys]}
        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview", return_value=preview
            ),
            mock.patch.object(
                intake.resources, "acquire_resources", return_value=acquired
            ) as acquire,
            mock.patch.object(
                intake.resources, "release_resources", return_value=released
            ) as release,
            mock.patch.object(intake, "_invoke_bureau", side_effect=invoke),
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root), lease_ttl_seconds=240
            )
        metadata = acquire.call_args.kwargs["metadata"]
        self.assertEqual(acquire.call_args.args[1], keys)
        self.assertEqual(metadata["task_id"], "INIT-T001")
        self.assertEqual(metadata["operation"], "registry-publication")
        self.assertEqual(metadata["proposal_sha256"], "c" * 64)
        self.assertEqual(acquire.call_args.kwargs["ttl_seconds"], 240)
        release.assert_called_once()
        self.assertTrue(result["leases_released"])
        self.assertTrue((directory / "publication-receipt.json").exists())

    def test_publish_state_store_mode_uses_state_root_and_single_state_lease(
        self,
    ) -> None:
        proposal_id = "1" * 64
        directory = self._write_proposal(proposal_id)
        state_root = "/home/alex/.local/state/bureau"
        keys = [f"path:{state_root}"]
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "publication_mode": "state_store",
            "coordination_state_root": state_root,
            "required_resource_keys": keys,
        }

        def invoke(arguments, **_kwargs):
            receipt = Path(arguments[arguments.index("--receipt") + 1])
            receipt.write_text(
                json.dumps(
                    {
                        "kind": "bureau_task_publication_receipt",
                        "status": "published",
                        "publication_mode": "state_store",
                        "coordination_state_root": state_root,
                    }
                )
                + "\n"
            )
            return {
                "kind": "bureau_task_publication_receipt",
                "status": "published",
                "publication_mode": "state_store",
                "coordination_state_root": state_root,
            }

        acquired = {"expires_at_unix": 200, "bureau_contract": {}}
        released = {"released": [{"resource_key": key} for key in keys]}
        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview", return_value=preview
            ) as preview_call,
            mock.patch.object(
                intake.resources, "acquire_resources", return_value=acquired
            ) as acquire,
            mock.patch.object(
                intake.resources, "release_resources", return_value=released
            ),
            mock.patch.object(intake, "_invoke_bureau", side_effect=invoke) as bureau_invoke,
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root), lease_ttl_seconds=240
            )

        preview_call.assert_called_once()
        self.assertEqual(acquire.call_args.args[1], keys)
        self.assertEqual(
            acquire.call_args.kwargs["metadata"]["operation"],
            "state-task-publication",
        )
        arguments = bureau_invoke.call_args.args[0]
        self.assertEqual(
            arguments[arguments.index("--state-root") + 1], state_root
        )
        self.assertEqual(
            bureau_invoke.call_args.kwargs["required_readback"],
            ["publication_receipt", "task_spec_revision", "resource_leases"],
        )
        self.assertTrue(result["leases_released"])
        self.assertTrue((directory / "publication-receipt.json").exists())

    def test_publish_state_store_receipt_replay_restores_explicit_state_root(
        self,
    ) -> None:
        proposal_id = "2" * 64
        directory = self._write_proposal(proposal_id)
        state_root = "/home/alex/.local/state/bureau"
        (directory / "publication-receipt.json").write_text(
            json.dumps(
                {
                    "kind": "bureau_task_publication_receipt",
                    "status": "published",
                    "publication_mode": "state_store",
                    "coordination_state_root": state_root,
                }
            )
            + "\n"
        )
        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview"
            ) as preview_call,
            mock.patch.object(
                intake,
                "_invoke_bureau",
                return_value={
                    "kind": "bureau_task_publication_receipt",
                    "status": "published",
                    "publication_mode": "state_store",
                },
            ) as invoke,
            mock.patch.object(intake.resources, "acquire_resources") as acquire,
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root)
            )

        preview_call.assert_not_called()
        acquire.assert_not_called()
        arguments = invoke.call_args.args[0]
        self.assertEqual(
            arguments[arguments.index("--state-root") + 1], state_root
        )
        self.assertFalse(result["leases_acquired"])
        self.assertTrue(result["idempotent_adapter_replay"])

    def test_publish_state_store_rejects_missing_root_before_lease_or_effect(
        self,
    ) -> None:
        proposal_id = "3" * 64
        self._write_proposal(proposal_id)
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "publication_mode": "state_store",
            "required_resource_keys": ["path:/home/alex/.local/state/bureau"],
        }
        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview", return_value=preview
            ),
            mock.patch.object(intake.resources, "acquire_resources") as acquire,
            mock.patch.object(intake, "_invoke_bureau") as invoke,
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root)
            )
        self.assertEqual(result["code"], "publication-state-root-contract-invalid")
        acquire.assert_not_called()
        invoke.assert_not_called()

    def test_publish_rejects_unknown_publication_mode_before_lease_or_effect(
        self,
    ) -> None:
        proposal_id = "4" * 64
        self._write_proposal(proposal_id)
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "publication_mode": "other",
            "required_resource_keys": ["path:/a", "path:/b"],
        }
        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview", return_value=preview
            ),
            mock.patch.object(intake.resources, "acquire_resources") as acquire,
            mock.patch.object(intake, "_invoke_bureau") as invoke,
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root)
            )
        self.assertEqual(result["code"], "publication-mode-contract-invalid")
        acquire.assert_not_called()
        invoke.assert_not_called()

    def test_publish_existing_receipt_replays_without_leases(self) -> None:
        proposal_id = "e" * 64
        directory = self._write_proposal(proposal_id)
        (directory / "publication-receipt.json").write_text(
            json.dumps({"kind": "bureau_task_publication_receipt"}) + "\n"
        )
        with (
            mock.patch.object(
                intake,
                "_invoke_bureau",
                return_value={
                    "kind": "bureau_task_publication_receipt",
                    "status": "published",
                    "idempotent_replay": True,
                },
            ) as invoke,
            mock.patch.object(intake.resources, "acquire_resources") as acquire,
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root)
            )
        acquire.assert_not_called()
        self.assertEqual(invoke.call_count, 1)
        self.assertFalse(result["leases_acquired"])
        self.assertTrue(result["idempotent_adapter_replay"])

    def test_publish_reconciles_ambiguity_from_created_receipt(self) -> None:
        proposal_id = "f" * 64
        self._write_proposal(proposal_id)
        keys = ["path:/a", "path:/b"]
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "required_resource_keys": keys,
        }
        calls = 0

        def invoke(arguments, **_kwargs):
            nonlocal calls
            calls += 1
            receipt = Path(arguments[arguments.index("--receipt") + 1])
            if calls == 1:
                receipt.write_text(
                    json.dumps({"kind": "bureau_task_publication_receipt"}) + "\n"
                )
                return {
                    "kind": "bureau_operator_intake_failure",
                    "code": "publication-unclear",
                    "effect_started": True,
                    "ambiguity": True,
                }
            return {
                "kind": "bureau_task_publication_receipt",
                "status": "published",
                "ambiguity": False,
            }

        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview", return_value=preview
            ),
            mock.patch.object(
                intake.resources,
                "acquire_resources",
                return_value={"expires_at_unix": 200, "bureau_contract": {}},
            ),
            mock.patch.object(
                intake.resources,
                "release_resources",
                return_value={"released": [{"resource_key": key} for key in keys]},
            ) as release,
            mock.patch.object(intake, "_invoke_bureau", side_effect=invoke),
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root)
            )
        self.assertEqual(calls, 2)
        release.assert_called_once()
        self.assertEqual(result["ambiguity_reconciled"], "receipt-replay")
        self.assertTrue(result["receipt_readback_attempted"])
        self.assertTrue(result["leases_released"])

    def test_publish_retains_leases_when_bureau_reports_ambiguity(self) -> None:
        proposal_id = "d" * 64
        self._write_proposal(proposal_id)
        keys = ["path:/a", "path:/b"]
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "required_resource_keys": keys,
        }
        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview", return_value=preview
            ),
            mock.patch.object(
                intake.resources,
                "acquire_resources",
                return_value={"expires_at_unix": 200, "bureau_contract": {}},
            ),
            mock.patch.object(intake.resources, "release_resources") as release,
            mock.patch.object(
                intake,
                "_invoke_bureau",
                return_value={
                    "kind": "bureau_operator_intake_failure",
                    "code": "publication-unclear",
                    "effect_started": True,
                    "ambiguity": True,
                    "required_readback": ["remote_branch", "pull_request"],
                },
            ),
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root)
            )
        release.assert_not_called()
        self.assertFalse(result["leases_released"])
        self.assertTrue(result["ambiguity"])


class BureauAuditFailureReasonTests(unittest.TestCase):
    """The audit chain must carry *why* a Bureau contract call was rejected."""

    def _record(self, payload: dict[str, object]) -> dict[str, object]:
        with mock.patch.object(intake.base, "_append_audit") as appended:
            intake._audit("bureau-candidate-record", payload, request_sha256="a" * 24)
        self.assertEqual(appended.call_count, 1)
        return appended.call_args.args[0]

    def test_failure_reason_and_retryability_are_recorded(self) -> None:
        record = self._record(
            {
                "kind": "bureau_operator_intake_failure",
                "status": "failed",
                "code": "candidate-record-invalid",
                "message": "candidate repo cannot change across supersession",
                "retryable": False,
                "effect_started": False,
                "ambiguity": False,
            }
        )

        self.assertEqual(record["bureau_code"], "candidate-record-invalid")
        self.assertEqual(
            record["bureau_failure_reason"],
            "candidate repo cannot change across supersession",
        )
        self.assertIs(record["bureau_retryable"], False)
        self.assertEqual(record["request_sha256"], "a" * 24)

    def test_successful_result_records_no_failure_reason(self) -> None:
        record = self._record(
            {
                "kind": "bureau_candidate_record_result",
                "status": "recorded",
                "message": "not a failure",
                "effect_started": True,
                "ambiguity": False,
            }
        )

        self.assertNotIn("bureau_failure_reason", record)
        self.assertNotIn("bureau_retryable", record)

    def test_reason_is_bounded_and_single_line(self) -> None:
        record = self._record(
            {
                "status": "failed",
                "code": "candidate-record-invalid",
                "message": "line one\n   line two\t" + "x" * 4000,
            }
        )

        reason = record["bureau_failure_reason"]
        self.assertEqual(len(reason), intake.AUDIT_FAILURE_REASON_MAX_CHARS)
        self.assertTrue(reason.startswith("line one line two x"))
        self.assertNotIn("\n", reason)
        self.assertTrue(reason.endswith("…"))

    def test_missing_or_empty_message_is_omitted(self) -> None:
        for message in (None, "", "   ", 17):
            with self.subTest(message=message):
                record = self._record(
                    {"status": "failed", "code": "x", "message": message}
                )
                self.assertNotIn("bureau_failure_reason", record)

    def test_explicit_extra_fields_still_win(self) -> None:
        record = self._record(
            {"status": "failed", "code": "x", "message": "boom", "retryable": True}
        )

        self.assertIs(record["bureau_retryable"], True)
        self.assertEqual(record["operation"], "bureau-candidate-record")


class BureauFailureIdentityTests(unittest.TestCase):
    @staticmethod
    def _binding(*, source_commit: str = "a" * 40) -> mock.Mock:
        return mock.Mock(
            source_commit=source_commit,
            registry_tree_sha256="b" * 64,
            launcher=mock.Mock(sha256="c" * 64),
            manifest=mock.Mock(sha256="d" * 64),
            inventory=mock.Mock(sha256="e" * 64),
        )

    def test_complete_contract_identity_is_bounded_stable_and_path_free(self) -> None:
        arguments = [
            "--json",
            "--json-envelope",
            "operator-task-publish",
            "--apply",
        ]
        identity = intake._bureau_contract_identity(arguments, self._binding())
        replay = intake._bureau_contract_identity(arguments, self._binding())

        self.assertEqual(identity["completeness"], "complete")
        self.assertEqual(identity["adapter"]["command"], "operator-task-publish")
        self.assertEqual(identity["adapter"]["mode"], "apply")
        self.assertEqual(identity["runtime"]["source_commit"], "a" * 40)
        self.assertEqual(identity["identity_sha256"], replay["identity_sha256"])
        self.assertNotIn("/", json.dumps(identity, sort_keys=True))
        self.assertNotIn("path", json.dumps(identity, sort_keys=True).casefold())

    def test_runtime_identity_change_separates_contract_identity(self) -> None:
        arguments = ["operator-candidate-record"]
        first = intake._bureau_contract_identity(
            arguments, self._binding(source_commit="a" * 40)
        )
        second = intake._bureau_contract_identity(
            arguments, self._binding(source_commit="f" * 40)
        )

        self.assertNotEqual(first["runtime"]["identity_sha256"], second["runtime"]["identity_sha256"])
        self.assertNotEqual(first["identity_sha256"], second["identity_sha256"])

    def test_unobserved_runtime_remains_partial(self) -> None:
        identity = intake._bureau_contract_identity(["operator-candidate-assess"])

        self.assertEqual(identity["completeness"], "partial")
        self.assertEqual(identity["runtime"], {"status": "unknown"})
        self.assertTrue(intake.SHA256_RE.fullmatch(identity["identity_sha256"]))

    def test_failure_audit_identity_binds_caller_surface(self) -> None:
        identity = intake._bureau_contract_identity(
            ["operator-candidate-record"], self._binding()
        )
        payload = {
            "kind": "bureau_operator_intake_failure",
            "status": "failed",
            "code": "candidate-record-invalid",
            "message": "bounded failure",
            "retryable": False,
            "bureau_contract_identity": identity,
        }
        with mock.patch.object(intake.base, "_append_audit") as appended:
            intake._audit("bureau-candidate-record", payload)
            intake._audit("bureau-task-propose", payload)

        first = appended.call_args_list[0].args[0]
        second = appended.call_args_list[1].args[0]
        self.assertEqual(first["bureau_caller_surface"], "bureau-candidate-record")
        self.assertEqual(first["bureau_contract_identity"], identity)
        self.assertEqual(
            first["bureau_result_schema_identity"]["kind"],
            "bureau_operator_intake_failure",
        )
        self.assertEqual(first["bureau_result_schema_identity"]["schema_version"], None)
        self.assertTrue(
            intake.SHA256_RE.fullmatch(first["bureau_failure_identity_sha256"])
        )
        self.assertNotEqual(
            first["bureau_failure_identity_sha256"],
            second["bureau_failure_identity_sha256"],
        )

    def test_failure_identity_separates_observed_result_schema_family(self) -> None:
        identity = intake._bureau_contract_identity(
            ["operator-candidate-record"], self._binding()
        )
        first_payload = {
            "schema_version": 1,
            "kind": "bureau_operator_intake_failure",
            "status": "failed",
            "code": "candidate-record-invalid",
            "bureau_contract_identity": identity,
        }
        second_payload = {
            **first_payload,
            "kind": "grabowski_bureau_intake_adapter_failure",
        }
        with mock.patch.object(intake.base, "_append_audit") as appended:
            intake._audit("bureau-candidate-record", first_payload)
            intake._audit("bureau-candidate-record", second_payload)

        first = appended.call_args_list[0].args[0]
        second = appended.call_args_list[1].args[0]
        self.assertNotEqual(
            first["bureau_result_schema_identity"]["sha256"],
            second["bureau_result_schema_identity"]["sha256"],
        )
        self.assertNotEqual(
            first["bureau_failure_identity_sha256"],
            second["bureau_failure_identity_sha256"],
        )

    def test_adapter_failure_is_audited_as_failed_with_retryability(self) -> None:
        identity = intake._bureau_contract_identity(["operator-candidate-assess"])
        payload = intake._adapter_failure(
            "bureau-runtime-unavailable",
            retryable=True,
            bureau_contract_identity=identity,
        )
        with mock.patch.object(intake.base, "_append_audit") as appended:
            intake._audit("bureau-candidate-assess", payload)

        record = appended.call_args.args[0]
        self.assertEqual(record["bureau_status"], "failed")
        self.assertEqual(record["bureau_code"], "bureau-runtime-unavailable")
        self.assertIs(record["bureau_retryable"], True)
        self.assertNotIn("bureau_failure_reason", record)
        self.assertEqual(
            record["bureau_contract_identity"]["completeness"], "partial"
        )



if __name__ == "__main__":
    unittest.main()
