from __future__ import annotations

from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import types
from typing import get_args
import unittest
from unittest import mock
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

class _FakeFastMCP:
    def tool(self, *args, **kwargs):
        return lambda function: function

class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

def _load_self_deploy():
    fake_mcp = types.ModuleType("mcp")
    fake_types = types.ModuleType("mcp.types")
    fake_types.ToolAnnotations = _FakeToolAnnotations
    fake_pydantic = types.ModuleType("pydantic")
    fake_pydantic.Field = lambda **kwargs: kwargs
    operator = types.ModuleType("grabowski_operator_core")
    operator.mcp = _FakeFastMCP()
    operator._require_operator_mutation = Mock()
    operator._require_operator_capability = Mock()
    operator.grabowski_job_start = Mock()
    operator._start_job = Mock()
    operator.JOB_PREFIX = "grabowski-job-"
    operator.JOBS_DIR = Path.home() / ".local/state/grabowski/jobs"
    operator._argv_hash = lambda argv: hashlib.sha256(
        json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    operator._jobs_root = Mock()
    operator._read_job_metadata = Mock()
    operator.grabowski_job_status = Mock()
    base = types.ModuleType("grabowski_mcp")
    base._append_audit = Mock()
    read_surface = types.ModuleType("grabowski_read_surface")
    read_surface._git_command = lambda repo, *args: ["git", "-C", str(repo), *args]
    read_surface._run_read = Mock()
    privileged = types.ModuleType("grabowski_privileged")
    privileged.ensure_rootbroker_authority = Mock(
        side_effect=lambda expected_head: {
            "success": True,
            "outcome": "already_current",
            "expected_head": expected_head,
            "attested_head": expected_head,
            "effect_started": False,
        }
    )
    name = "grabowski_self_deploy_test"
    spec = importlib.util.spec_from_file_location(name, ROOT / "src" / "grabowski_self_deploy.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load self deploy module")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"mcp": fake_mcp, "mcp.types": fake_types, "pydantic": fake_pydantic, "grabowski_operator_core": operator, "grabowski_mcp": base, "grabowski_read_surface": read_surface, "grabowski_privileged": privileged, name: module}, clear=False):
        spec.loader.exec_module(module)
    return module

def _result(stdout: str = "", returncode: int = 0) -> dict[str, object]:
    return {"returncode": returncode, "timed_out": False, "stdout_truncated": False, "stderr_truncated": False, "stdout": stdout, "stderr": ""}

SELF_DEPLOY = _load_self_deploy()
REAL_FRESH_PUBLIC_GITHUB_MAIN = SELF_DEPLOY._fresh_public_github_main
SELF_DEPLOY._fresh_public_github_main = Mock(
    side_effect=lambda expected_head: expected_head
)

def _source_identity(repo: Path, head: str, *, kind: str = "canonical-main", canonical: Path | None = None) -> dict[str, object]:
    canonical_repo = canonical or repo
    material = {
        "schema_version": 1,
        "kind": "grabowski_runtime_deploy_source_identity",
        "source_kind": kind,
        "repository": str(repo),
        "canonical_repository": str(canonical_repo),
        "git_common_directory": str(canonical_repo / ".git"),
        "head": head,
        "origin_main": head,
        "clean": True,
        "lease_evidence": {"resource_key": f"path:{repo}", "lease": None},
    }
    return {**material, "identity_sha256": SELF_DEPLOY._source_identity_sha256(material)}

RUNNER_SPEC = importlib.util.spec_from_file_location("run_scheduled_deploy_test", ROOT / "tools" / "run_scheduled_deploy.py")
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError("cannot load scheduled deployment runner")
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)

SCHEDULER_SPEC = importlib.util.spec_from_file_location("schedule_runtime_deploy_test", ROOT / "tools" / "schedule_runtime_deploy.py")
if SCHEDULER_SPEC is None or SCHEDULER_SPEC.loader is None:
    raise RuntimeError("cannot load runtime deployment scheduler")
SCHEDULER = importlib.util.module_from_spec(SCHEDULER_SPEC)
SCHEDULER_SPEC.loader.exec_module(SCHEDULER)


def _dispatcher_metrics(
    *,
    queue: float = 0.0,
    workers: float = 0.0,
    polled: float = 7.0,
    enqueued: float = 7.0,
    responses: float = 7.0,
    process_start: float = 100.0,
) -> dict[str, float]:
    return {
        "commands_queue_length": queue,
        "dispatcher_worker_pool_occupancy": workers,
        "commands_polled_total": polled,
        "commands_enqueued_total": enqueued,
        "commands_final_responses_total": responses,
        "process_start_time_seconds": process_start,
    }


def _contention_result(*, decision: str = "proceed") -> dict[str, object]:
    return {
        "decision": decision,
        "lock": {"state": "available" if decision == "proceed" else "busy"},
        "dispatcher": {"state": "idle"},
    }

def _sidecar_controller_contract() -> dict[str, object]:
    return {
        "decision": "controller",
        "controller": "grabowski-primary",
        "primary_role": "controller-integrator",
        "delegated_scoped_writers_allowed": True,
        "controller_integration_required": True,
        "single_mutating_writer": True,
        "single_mutating_writer_scope": "overlapping-resource-lane",
        "external_primary_writer_forbidden": False,
        "automatic_execution_authorized": True,
    }


def _sidecar_apply_receipt() -> dict[str, object]:
    return {
        "kind": "coding-agent-router-cli-install-receipt",
        "status": "installed",
        "installed": True,
        "runtime_catalog_source": "deployment_catalog",
        "runtime_catalog_sha256": "c" * 64,
        "wrapper_sha256": "a" * 64,
        "scheduler_sha256": "b" * 64,
        "automatic_execution_authorized": True,
        "rollback_performed": False,
        "readback": {
            **_sidecar_controller_contract(),
            "catalog_sha256": "c" * 64,
        },
    }


def _sidecar_check_receipt() -> dict[str, object]:
    return {
        "kind": "coding-agent-router-cli-install-check",
        "installed": True,
        "runtime_catalog_source": "deployment_catalog",
        "runtime_catalog_sha256": "c" * 64,
        "wrapper_sha256": "a" * 64,
        "scheduler_sha256": "b" * 64,
        **_sidecar_controller_contract(),
        "catalog_sha256": "c" * 64,
    }


def _sidecar_reconciliation(expected: str = "f" * 40) -> dict[str, object]:
    material = {
        "schema_version": 1,
        "kind": RUNNER.SIDECAR_RECONCILIATION_KIND,
        "status": "installed",
        "repo_head": expected,
        "release_id": "r",
        "wrapper_sha256": "a" * 64,
        "scheduler_sha256": "b" * 64,
        "runtime_catalog_sha256": "c" * 64,
        "apply_receipt_sha256": RUNNER.canonical_json_sha256(
            _sidecar_apply_receipt()
        ),
        "check_receipt_sha256": RUNNER.canonical_json_sha256(
            _sidecar_check_receipt()
        ),
        "automatic_execution_authorized": True,
    }
    return {**material, "evidence_sha256": RUNNER.canonical_json_sha256(material)}


def _productive_blue_green_result(expected: str = "f" * 40) -> dict[str, object]:
    summary = {
        "schema_version": 1,
        "kind": "grabowski_scheduled_blue_green_summary",
        "receipt_sha256": "ab" * 32,
        "receipt_path": "/state/blue-green.json",
        "receipt_persisted": True,
        "receipt_persistence_error_type": None,
        "blind_retry_allowed": None,
        "outcome": "completed",
        "expected_head": expected,
        "source_identity_sha256": "cd" * 32,
    }
    return {
        "outcome": "completed",
        "receipt_sha256": "ab" * 32,
        "receipt_path": "/state/blue-green.json",
        "receipt_persisted": True,
        "receipt": {
            "receipt_sha256": "ab" * 32,
            "outcome": "completed",
            "expected_head": expected,
        },
        "summary": summary,
    }


def _unpersisted_productive_blue_green_result(expected: str = "f" * 40) -> dict[str, object]:
    result = _productive_blue_green_result(expected)
    summary = dict(result["summary"])
    summary.update(
        {
            "receipt_path": None,
            "receipt_persisted": False,
            "receipt_persistence_error_type": "OSError",
            "blind_retry_allowed": False,
        }
    )
    return {
        **result,
        "receipt_path": None,
        "receipt_persisted": False,
        "receipt_persistence_error_type": "OSError",
        "summary": summary,
    }


def _unpersisted_outcome_unknown_blue_green_result(
    expected: str = "f" * 40,
) -> dict[str, object]:
    result = _unpersisted_productive_blue_green_result(expected)
    receipt = dict(result["receipt"])
    receipt["outcome"] = "outcome_unknown"
    summary = dict(result["summary"])
    summary["outcome"] = "outcome_unknown"
    return {
        **result,
        "outcome": "outcome_unknown",
        "receipt": receipt,
        "summary": summary,
    }


class SelfDeployToolTests(unittest.TestCase):
    def test_annotations_and_schema_bounds(self) -> None:
        self.assertFalse(SELF_DEPLOY.DEPLOY_MUTATING.readOnlyHint)
        self.assertFalse(SELF_DEPLOY.DEPLOY_MUTATING.destructiveHint)
        self.assertFalse(SELF_DEPLOY.DEPLOY_MUTATING.idempotentHint)
        self.assertTrue(SELF_DEPLOY.DEPLOY_MUTATING.openWorldHint)
        self.assertEqual(get_args(SELF_DEPLOY.DelaySeconds)[1]["ge"], 5)
        self.assertEqual(get_args(SELF_DEPLOY.DelaySeconds)[1]["le"], 60)

    def test_deploy_index_round_trip_is_private_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            unit = "grabowski-job-abcdef012345"
            written = SELF_DEPLOY._write_deploy_index(
                jobs,
                units=[unit],
                pending_unit=None,
            )
            loaded = SELF_DEPLOY._read_deploy_index(jobs)
            self.assertEqual(loaded, written)
            self.assertEqual(
                (jobs / SELF_DEPLOY.DEPLOY_INDEX_FILENAME).stat().st_mode & 0o777,
                0o600,
            )

    def test_deploy_index_rejects_hardlinks_and_non_private_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            SELF_DEPLOY._write_deploy_index(jobs, units=[], pending_unit=None)
            (root / "index-hardlink").hardlink_to(
                jobs / SELF_DEPLOY.DEPLOY_INDEX_FILENAME
            )
            with self.assertRaisesRegex(RuntimeError, "one private owner-controlled"):
                SELF_DEPLOY._read_deploy_index(jobs)
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            jobs.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "private and owner-controlled"):
                SELF_DEPLOY._read_deploy_index(jobs)

    def test_index_bootstrap_excludes_terminal_self_deploy_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            repository = root / "repo"
            runner = repository / SELF_DEPLOY.RUNNER_RELATIVE_PATH
            terminal = "grabowski-job-111111111111"
            running = "grabowski-job-222222222222"
            (jobs / terminal).mkdir(mode=0o700)
            (jobs / running).mkdir(mode=0o700)
            metadata = {
                terminal: {
                    "argv": ["/usr/bin/python3", str(runner)],
                    "final_status": "completed",
                },
                running: {
                    "argv": ["/usr/bin/python3", str(runner)],
                    "final_status": "running",
                },
            }
            with patch.object(
                SELF_DEPLOY.operator,
                "_read_job_metadata",
                side_effect=lambda unit: metadata[unit],
            ):
                index = SELF_DEPLOY._bootstrap_deploy_index(jobs, repository)
            self.assertEqual(index["units"], [running])

    def test_bootstrap_retry_block_preserves_unpersisted_outcome_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            entry = Path(temporary) / "grabowski-job-abcdef012345"
            entry.mkdir(mode=0o700)
            expected = "a" * 40
            receipt_sha256 = "ab" * 32
            contract = {
                "kind": "grabowski_runtime_deploy_finalization",
                "unit": entry.name,
                "job_id": "abcdef012345",
                "argv_sha256": "b" * 64,
                "expected_head": expected,
                "receipt_paths": {"finalization": str(entry / "finalization.json")},
            }
            material = {
                "unit": entry.name,
                "job_id": "abcdef012345",
                "argv_sha256": "b" * 64,
                "expected_head": expected,
                "final_status": "outcome_unknown",
                "completion_status": "outcome_unknown",
                "blue_green": {
                    "receipt_sha256": receipt_sha256,
                    "receipt_persisted": False,
                    "outcome": "outcome_unknown",
                    "expected_head": expected,
                },
                "blue_green_receipt_sha256": receipt_sha256,
                "blind_retry_allowed": False,
            }
            payload = {**material, "payload_sha256": SELF_DEPLOY._sha256_json(material)}
            receipt = entry / "finalization.json"
            receipt.write_text(json.dumps(payload), encoding="utf-8")
            receipt.chmod(0o600)
            self.assertTrue(
                SELF_DEPLOY._deploy_finalization_retry_block(
                    entry, {"finalization_contract": contract}
                )
            )

    def test_pending_deploy_index_unit_is_recovered_from_exact_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "jobs"
            jobs.mkdir(mode=0o700)
            unit = "grabowski-job-abcdef012345"
            (jobs / unit).mkdir(mode=0o700)
            SELF_DEPLOY._write_deploy_index(
                jobs,
                units=[],
                pending_unit=unit,
            )
            index = SELF_DEPLOY._deploy_index(jobs, Path(temporary))
            self.assertEqual(index["units"], [unit])
            self.assertIsNone(index["pending_unit"])

    def test_preflight_requires_clean_synchronized_main(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            (repo / ".git").mkdir()
            runner = repo / "tools" / "run_scheduled_deploy.py"
            runner.parent.mkdir()
            runner.write_text("pass\n", encoding="utf-8")
            expected = "a" * 40
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", repo), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[
                    _result(".git"),
                    _result(expected),
                    _result("main"),
                    _result(expected),
                    _result(""),
                ],
            ), patch.object(
                SELF_DEPLOY,
                "_resource_inspect",
                return_value={"resource_key": f"path:{repo}", "lease": None},
            ):
                resolved_repo, resolved_runner, identity = SELF_DEPLOY._deployment_source_preflight(
                    expected, None, None
                )
            self.assertEqual(resolved_repo, repo)
            self.assertEqual(resolved_runner, runner)
            self.assertEqual(identity["source_kind"], "canonical-main")
            self.assertEqual(identity["head"], expected)
            self.assertEqual(identity["lease_evidence"]["lease"], None)

    def test_canonical_preflight_ignores_expired_foreign_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            (repo / ".git").mkdir()
            runner = repo / "tools" / "run_scheduled_deploy.py"
            runner.parent.mkdir()
            runner.write_text("pass\n", encoding="utf-8")
            expected = "a" * 40
            lease = {
                "resource_key": f"path:{repo}",
                "owner_id": "foreign-owner",
                "acquired_at_unix": 10,
                "updated_at_unix": 11,
                "expires_at_unix": 50,
                "metadata_sha256": "a" * 64,
            }
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", repo), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[
                    _result(".git"),
                    _result(expected),
                    _result("main"),
                    _result(expected),
                    _result(""),
                ],
            ), patch.object(SELF_DEPLOY.time, "time", return_value=50), patch.object(
                SELF_DEPLOY,
                "_resource_inspect",
                return_value={"resource_key": f"path:{repo}", "lease": lease},
            ):
                resolved, _runner, identity = SELF_DEPLOY._deployment_source_preflight(
                    expected, None, None
                )
            self.assertEqual(resolved, repo)
            self.assertIsNone(identity["lease_evidence"]["lease"])

    def test_detached_preflight_rejects_expired_expected_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            canonical = root / "canonical"
            source = root / "source"
            canonical.mkdir()
            source.mkdir()
            common = canonical / ".git"
            common.mkdir()
            runner = source / "tools" / "run_scheduled_deploy.py"
            runner.parent.mkdir()
            runner.write_text("pass\n", encoding="utf-8")
            expected = "b" * 40
            lease = {
                "resource_key": f"path:{source}",
                "owner_id": "task:deploy-source",
                "acquired_at_unix": 10,
                "updated_at_unix": 11,
                "expires_at_unix": 50,
                "metadata_sha256": "a" * 64,
            }
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", canonical), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[
                    _result(str(common)),
                    _result(str(common)),
                    _result(expected),
                    _result("HEAD"),
                    _result(expected),
                    _result(""),
                ],
            ), patch.object(SELF_DEPLOY.time, "time", return_value=50), patch.object(
                SELF_DEPLOY,
                "_resource_inspect",
                return_value={"resource_key": f"path:{source}", "lease": lease},
            ):
                with self.assertRaisesRegex(RuntimeError, "absent or expired"):
                    SELF_DEPLOY._deployment_source_preflight(
                        expected, str(source), "task:deploy-source"
                    )

    def test_source_lease_malformed_expiry_fails_closed(self) -> None:
        repo = Path("/home/alex/repos/.grabowski-worktrees/deploy-malformed")
        lease = {
            "resource_key": f"path:{repo}",
            "owner_id": "task:deploy-source",
            "acquired_at_unix": 10,
            "updated_at_unix": 11,
            "expires_at_unix": "invalid",
            "metadata_sha256": "a" * 64,
        }
        payload = {"resource_key": f"path:{repo}", "lease": lease}
        with patch.object(SELF_DEPLOY, "_resource_inspect", return_value=payload):
            self.assertEqual(
                SELF_DEPLOY._source_lease_evidence(repo, None),
                {"resource_key": f"path:{repo}", "lease": None},
            )
            with self.assertRaisesRegex(RuntimeError, "absent or expired"):
                SELF_DEPLOY._source_lease_evidence(repo, "task:deploy-source")

    def test_preflight_rejects_dirty_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            (repo / ".git").mkdir()
            runner = repo / "tools" / "run_scheduled_deploy.py"
            runner.parent.mkdir()
            runner.write_text("pass\n", encoding="utf-8")
            expected = "b" * 40
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", repo), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[
                    _result(".git"),
                    _result(expected),
                    _result("main"),
                    _result(expected),
                    _result(" M file"),
                ],
            ):
                with self.assertRaisesRegex(RuntimeError, "dirty"):
                    SELF_DEPLOY._deployment_source_preflight(expected, None, None)

    def test_preflight_rejects_repoground_managed_source_before_git_or_lease_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            canonical = root / "canonical"
            managed_root = root / ".repoground-sources"
            source = managed_root / "heimgewebe__grabowski__main"
            canonical.mkdir()
            source.mkdir(parents=True)
            expected = "d" * 40
            with patch.object(
                SELF_DEPLOY, "CANONICAL_REPOSITORY", canonical
            ), patch.object(
                SELF_DEPLOY, "REPOGROUND_MANAGED_SOURCE_ROOT", managed_root
            ), patch.dict(
                os.environ, {"REPOGROUND_SOURCE_ROOT": str(root / "configured-root")}
            ), patch.object(
                SELF_DEPLOY, "_git_common_directory"
            ) as git_common, patch.object(
                SELF_DEPLOY, "_resource_inspect"
            ) as resource_inspect:
                with self.assertRaisesRegex(RuntimeError, "RepoGround-managed"):
                    SELF_DEPLOY._deployment_source_preflight(
                        expected,
                        str(source),
                        "task:deploy-source",
                    )
            git_common.assert_not_called()
            resource_inspect.assert_not_called()

    def test_explicit_detached_worktree_source_is_identity_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            canonical = root / "canonical"
            source = root / "source"
            canonical.mkdir()
            source.mkdir()
            common = canonical / ".git"
            common.mkdir()
            runner = source / "tools" / "run_scheduled_deploy.py"
            runner.parent.mkdir()
            runner.write_text("pass\n", encoding="utf-8")
            expected = "d" * 40
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", canonical), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[
                    _result(str(common)),
                    _result(str(common)),
                    _result(expected),
                    _result("HEAD"),
                    _result(expected),
                    _result(""),
                ],
            ), patch.object(
                SELF_DEPLOY.time, "time", return_value=50
            ), patch.object(
                SELF_DEPLOY,
                "_resource_inspect",
                return_value={
                    "resource_key": f"path:{source}",
                    "lease": {
                        "resource_key": f"path:{source}",
                        "owner_id": "task:deploy-source",
                        "acquired_at_unix": 10,
                        "updated_at_unix": 11,
                        "expires_at_unix": 100,
                        "metadata_sha256": "a" * 64,
                    },
                },
            ):
                resolved, resolved_runner, identity = SELF_DEPLOY._deployment_source_preflight(
                    expected,
                    str(source),
                    "task:deploy-source",
                )
            self.assertEqual(resolved, source)
            self.assertEqual(resolved_runner, runner)
            self.assertEqual(identity["source_kind"], "detached-worktree")
            self.assertEqual(identity["canonical_repository"], str(canonical))
            self.assertRegex(identity["identity_sha256"], r"[0-9a-f]{64}")
            self.assertEqual(
                identity["lease_evidence"]["lease"]["owner_id"],
                "task:deploy-source",
            )

    def test_detached_source_requires_lease_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            canonical = root / "canonical"
            source = root / "source"
            canonical.mkdir()
            source.mkdir()
            common = canonical / ".git"
            common.mkdir()
            runner = source / "tools" / "run_scheduled_deploy.py"
            runner.parent.mkdir()
            runner.write_text("pass\n", encoding="utf-8")
            expected = "d" * 40
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", canonical), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[
                    _result(str(common)),
                    _result(str(common)),
                    _result(expected),
                    _result("HEAD"),
                    _result(expected),
                    _result(""),
                ],
            ):
                with self.assertRaisesRegex(ValueError, "requires source_lease_owner_id"):
                    SELF_DEPLOY._deployment_source_preflight(
                        expected,
                        str(source),
                        None,
                    )

    def test_explicit_source_rejects_topic_branch_and_foreign_git_common_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            canonical = root / "canonical"
            source = root / "source"
            canonical.mkdir()
            source.mkdir()
            common = canonical / ".git"
            foreign = root / "foreign.git"
            common.mkdir()
            foreign.mkdir()
            runner = source / "tools" / "run_scheduled_deploy.py"
            runner.parent.mkdir()
            runner.write_text("pass\n", encoding="utf-8")
            expected = "e" * 40
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", canonical), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[_result(str(common)), _result(str(foreign))],
            ):
                with self.assertRaisesRegex(RuntimeError, "does not share"):
                    SELF_DEPLOY._deployment_source_preflight(expected, str(source), None)
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", canonical), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[
                    _result(str(common)),
                    _result(str(common)),
                    _result(expected),
                    _result("topic"),
                    _result(expected),
                    _result(""),
                ],
            ):
                with self.assertRaisesRegex(RuntimeError, "invalid branch state"):
                    SELF_DEPLOY._deployment_source_preflight(expected, str(source), None)

    def test_source_lease_requires_exact_owner_and_enters_identity(self) -> None:
        repo = Path("/home/alex/repos/.grabowski-worktrees/deploy")
        lease = {
            "resource_key": f"path:{repo}",
            "owner_id": "task:deploy-owner",
            "acquired_at_unix": 10,
            "updated_at_unix": 11,
            "expires_at_unix": 100,
            "metadata_sha256": "a" * 64,
        }
        payload = {"resource_key": f"path:{repo}", "lease": lease}
        with patch.object(SELF_DEPLOY.time, "time", return_value=50), patch.object(
            SELF_DEPLOY, "_resource_inspect", return_value=payload
        ):
            with self.assertRaisesRegex(RuntimeError, "active lease"):
                SELF_DEPLOY._source_lease_evidence(repo, None)
            with self.assertRaisesRegex(RuntimeError, "owner drift"):
                SELF_DEPLOY._source_lease_evidence(repo, "task:other")
            evidence = SELF_DEPLOY._source_lease_evidence(repo, "task:deploy-owner")
        self.assertEqual(evidence["lease"], lease)
        first = _source_identity(repo, "a" * 40, kind="detached-worktree", canonical=Path("/home/alex/repos/grabowski"))
        material = {key: value for key, value in first.items() if key != "identity_sha256"}
        material["lease_evidence"] = evidence
        second_hash = SELF_DEPLOY._source_identity_sha256(material)
        self.assertNotEqual(first["identity_sha256"], second_hash)
        command_a = SELF_DEPLOY._deploy_command(
            repo,
            repo / "tools/run_scheduled_deploy.py",
            "a" * 40,
            8,
            canonical_repository=Path("/home/alex/repos/grabowski"),
            source_kind="detached-worktree",
            source_identity_sha256=first["identity_sha256"],
        )
        command_b = SELF_DEPLOY._deploy_command(
            repo,
            repo / "tools/run_scheduled_deploy.py",
            "a" * 40,
            8,
            canonical_repository=Path("/home/alex/repos/grabowski"),
            source_kind="detached-worktree",
            source_identity_sha256=second_hash,
        )
        self.assertNotEqual(
            SELF_DEPLOY._deploy_identity(command_a),
            SELF_DEPLOY._deploy_identity(command_b),
        )

    def test_source_path_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            canonical = root / "canonical"
            target = root / "target"
            canonical.mkdir()
            target.mkdir()
            source = root / "source"
            source.symlink_to(target, target_is_directory=True)
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", canonical):
                with self.assertRaisesRegex(RuntimeError, "unavailable"):
                    SELF_DEPLOY._deployment_source_preflight("a" * 40, str(source), None)

    def test_schedule_uses_fixed_delayed_runner(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        expected = "c" * 40
        identity = _source_identity(repo, expected)
        unit = "grabowski-job-abcdef012345"
        job_dir = Path("/state") / unit
        command = SELF_DEPLOY._deploy_command(
            repo,
            runner,
            expected,
            9,
            canonical_repository=repo,
            source_kind="canonical-main",
            source_identity_sha256=identity["identity_sha256"],
        )
        job = {
            "unit": unit,
            "argv_sha256": SELF_DEPLOY.operator._argv_hash(command),
            "metadata_path": str(job_dir / "metadata.json"),
            "stdout_path": str(job_dir / "stdout.log"),
            "stderr_path": str(job_dir / "stderr.log"),
        }
        SELF_DEPLOY.operator._start_job.reset_mock()
        SELF_DEPLOY.base._append_audit.reset_mock()
        SELF_DEPLOY.operator._start_job.return_value = job
        fixed_uuid = Mock(hex="abcdef012345ffffffffffffffffffff")
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            return_value=(repo, runner, identity),
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(SELF_DEPLOY, "_matching_inflight_deploy_job", return_value=None), patch.object(
            SELF_DEPLOY.operator, "_jobs_root", return_value=Path("/state")
        ), patch.object(
            SELF_DEPLOY, "_deploy_index", return_value={"units": [], "pending_unit": None}
        ), patch.object(SELF_DEPLOY, "_write_deploy_index") as write_index, patch.object(
            SELF_DEPLOY.uuid, "uuid4", return_value=fixed_uuid
        ):
            result = SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 9)
        SELF_DEPLOY.operator._start_job.assert_called_once_with(
            command,
            cwd=str(repo),
            runtime_seconds=3600,
            finalization_expected_head=expected,
            reserved_unit=unit,
            allow_reserved_runtime_deploy=True,
        )
        self.assertEqual(write_index.call_count, 2)
        self.assertTrue(result["scheduled"])
        self.assertFalse(result["already_scheduled"])
        self.assertEqual(result["source_identity_sha256"], identity["identity_sha256"])
        self.assertEqual(result["unit"], unit)
        self.assertEqual(SELF_DEPLOY.base._append_audit.call_count, 2)

    def test_public_github_main_lookup_is_fixed_and_credential_free(self) -> None:
        expected = "d" * 40
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=f"{expected}\trefs/heads/main\n",
            stderr="",
        )
        with patch.object(SELF_DEPLOY.subprocess, "run", return_value=completed) as run:
            observed = REAL_FRESH_PUBLIC_GITHUB_MAIN(expected)
        self.assertEqual(observed, expected)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/git")
        self.assertIn("credential.helper=", argv)
        self.assertEqual(argv[-2:], [SELF_DEPLOY.PUBLIC_GITHUB_REPOSITORY_URL, SELF_DEPLOY.PUBLIC_GITHUB_MAIN_REF])
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["cwd"], "/")
        self.assertEqual(kwargs["timeout"], SELF_DEPLOY.PUBLIC_GITHUB_LOOKUP_TIMEOUT_SECONDS)
        env = kwargs["env"]
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GIT_ASKPASS"], "/bin/false")
        self.assertNotIn("HOME", env)
        self.assertFalse(any("PROXY" in key.upper() for key in env))

    def test_schedule_blocks_when_public_github_main_differs_before_root_effect(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        expected = "d" * 40
        identity = _source_identity(repo, expected)
        SELF_DEPLOY.privileged.ensure_rootbroker_authority.reset_mock()
        SELF_DEPLOY.operator._start_job.reset_mock()
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            return_value=(repo, runner, identity),
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(
            SELF_DEPLOY, "_fresh_public_github_main", return_value="e" * 40
        ):
            with self.assertRaisesRegex(RuntimeError, "public GitHub main differs"):
                SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 8)
        SELF_DEPLOY.privileged.ensure_rootbroker_authority.assert_not_called()
        SELF_DEPLOY.operator._start_job.assert_not_called()

    def test_schedule_blocks_when_public_github_main_drifts_during_root_refresh(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        expected = "d" * 40
        identity = _source_identity(repo, expected)
        SELF_DEPLOY.operator._start_job.reset_mock()
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            return_value=(repo, runner, identity),
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(
            SELF_DEPLOY,
            "_fresh_public_github_main",
            side_effect=[expected, "e" * 40],
        ), patch.object(
            SELF_DEPLOY.privileged,
            "ensure_rootbroker_authority",
            return_value={
                "success": True,
                "outcome": "succeeded",
                "expected_head": expected,
                "attested_head": expected,
                "effect_started": True,
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "GitHub main drifted"):
                SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 8)
        SELF_DEPLOY.operator._start_job.assert_not_called()

    def test_schedule_blocks_when_rootbroker_authority_refresh_fails(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        expected = "d" * 40
        identity = _source_identity(repo, expected)
        SELF_DEPLOY.operator._start_job.reset_mock()
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            return_value=(repo, runner, identity),
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(
            SELF_DEPLOY.privileged,
            "ensure_rootbroker_authority",
            return_value={
                "success": False,
                "outcome": "failed",
                "failure_reason": "authority mismatch",
            },
        ), patch.object(
            SELF_DEPLOY, "_matching_inflight_deploy_job"
        ) as lookup:
            with self.assertRaisesRegex(RuntimeError, "authority refresh failed"):
                SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 8)
        lookup.assert_not_called()
        SELF_DEPLOY.operator._start_job.assert_not_called()

    def test_schedule_rejects_source_identity_drift_during_authority_refresh(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        expected = "d" * 40
        before = _source_identity(repo, expected)
        after = dict(before)
        after["identity_sha256"] = "9" * 64
        SELF_DEPLOY.operator._start_job.reset_mock()
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            side_effect=[(repo, runner, before), (repo, runner, after)],
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(
            SELF_DEPLOY.privileged,
            "ensure_rootbroker_authority",
            return_value={
                "success": True,
                "outcome": "succeeded",
                "expected_head": expected,
                "attested_head": expected,
                "effect_started": True,
            },
        ), patch.object(
            SELF_DEPLOY, "_matching_inflight_deploy_job"
        ) as lookup:
            with self.assertRaisesRegex(RuntimeError, "source identity drifted"):
                SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 8)
        lookup.assert_not_called()
        SELF_DEPLOY.operator._start_job.assert_not_called()

    def test_schedule_reuses_identical_inflight_job_without_starting_another(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        expected = "e" * 40
        identity = _source_identity(repo, expected)
        existing = {
            "unit": "grabowski-job-abcdef012345",
            "argv_sha256": "f" * 64,
            "delay_seconds": 6,
            "metadata_path": "/state/meta",
            "stdout_path": "/state/out",
            "stderr_path": "/state/err",
            "final_status": "running",
        }
        SELF_DEPLOY.operator.grabowski_job_start.reset_mock()
        SELF_DEPLOY.base._append_audit.reset_mock()
        command = SELF_DEPLOY._deploy_command(
            repo,
            runner,
            expected,
            8,
            canonical_repository=repo,
            source_kind="canonical-main",
            source_identity_sha256=identity["identity_sha256"],
        )
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            return_value=(repo, runner, identity),
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(SELF_DEPLOY, "_matching_inflight_deploy_job", return_value=existing) as lookup:
            result = SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 8)
        lookup.assert_called_once_with(command, repo)
        SELF_DEPLOY.operator.grabowski_job_start.assert_not_called()
        self.assertTrue(result["already_scheduled"])
        self.assertEqual(result["source_identity_sha256"], identity["identity_sha256"])
        self.assertEqual(1, SELF_DEPLOY.base._append_audit.call_count)

    def test_schedule_reports_effective_source_when_reusing_same_target(self) -> None:
        canonical = Path("/home/alex/repos/grabowski")
        requested_repo = Path(
            "/home/alex/repos/.grabowski-worktrees/deploy-requested"
        )
        expected = "e" * 40
        requested_identity = _source_identity(
            requested_repo,
            expected,
            kind="detached-worktree",
            canonical=canonical,
        )
        existing = {
            "unit": "grabowski-job-abcdef012345",
            "argv_sha256": "f" * 64,
            "delay_seconds": 6,
            "metadata_path": "/state/meta",
            "stdout_path": "/state/out",
            "stderr_path": "/state/err",
            "final_status": "running",
            "source_identity_sha256": "1" * 64,
        }
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            return_value=(
                requested_repo,
                requested_repo / "tools/run_scheduled_deploy.py",
                requested_identity,
            ),
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(
            SELF_DEPLOY, "_matching_inflight_deploy_job", return_value=existing
        ), patch.object(SELF_DEPLOY.base, "_append_audit") as audit:
            result = SELF_DEPLOY.grabowski_runtime_deploy_schedule(
                expected,
                8,
                str(requested_repo),
                "task:deploy-requested",
            )
        self.assertTrue(result["already_scheduled"])
        self.assertEqual(
            requested_identity["identity_sha256"],
            result["source_identity_sha256"],
        )
        self.assertEqual("1" * 64, result["effective_source_identity_sha256"])
        self.assertTrue(result["reused_across_source_identity"])
        observed = audit.call_args.args[0]
        self.assertEqual("1" * 64, observed["effective_source_identity_sha256"])
        self.assertTrue(observed["reused_across_source_identity"])

    def test_deploy_identity_accepts_canonical_options_in_any_order(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        head = "a" * 40
        command = [
            "/usr/bin/python3",
            str(runner),
            "--delay-seconds",
            "8",
            "--source-kind",
            "canonical-main",
            "--source-identity-sha256",
            "0" * 64,
            "--expected-head",
            head,
            "--canonical-repo",
            str(repo),
            "--repo",
            str(repo),
        ]
        self.assertEqual(
            (
                "/usr/bin/python3",
                str(runner),
                str(repo),
                str(repo),
                "canonical-main",
                "0" * 64,
                head,
            ),
            SELF_DEPLOY._deploy_identity(command),
        )

    def test_deploy_identity_rejects_duplicate_or_unknown_options(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        head = "a" * 40
        duplicate = [
            "/usr/bin/python3", str(runner),
            "--repo", str(repo),
            "--repo", str(repo),
            "--expected-head", head,
        ]
        unknown = [
            "/usr/bin/python3", str(runner),
            "--repo", str(repo),
            "--expected-head", head,
            "--force", "8",
        ]
        self.assertIsNone(SELF_DEPLOY._deploy_identity(duplicate))
        self.assertIsNone(SELF_DEPLOY._deploy_identity(unknown))

    def test_matching_inflight_job_uses_deploy_identity_and_receipt(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        command = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            expected_receipt = {
                "metadata_path": str(job_dir / "metadata.json"),
                "stdout_path": str(job_dir / "stdout.log"),
                "stderr_path": str(job_dir / "stderr.log"),
            }
            with patch.object(
                SELF_DEPLOY.operator, "_jobs_root", return_value=root, create=True
            ), patch.object(SELF_DEPLOY.operator, "JOB_PREFIX", "grabowski-job-", create=True), patch.object(
                SELF_DEPLOY.operator,
                "_read_job_metadata",
                return_value={
                    "argv": SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 6),
                    "argv_sha256": SELF_DEPLOY.operator._argv_hash(SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 6)),
                    "cwd": str(repo),
                    "expected_receipt": {
                        "unit": "grabowski-job-abcdef012345",
                        "metadata_path": str(job_dir / "metadata.json"),
                        "stdout_path": str(job_dir / "stdout.log"),
                        "stderr_path": str(job_dir / "stderr.log"),
                        "status_tool": "grabowski_job_status",
                        "logs_tool": "grabowski_job_logs",
                    },
                },
                create=True,
            ), patch.object(
                SELF_DEPLOY.operator,
                "grabowski_job_status",
                return_value={
                    "final_status": "running",
                    "metadata": {"expected_receipt": expected_receipt},
                },
                create=True,
            ):
                result = SELF_DEPLOY._matching_inflight_deploy_job(command, repo)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("grabowski-job-abcdef012345", result["unit"])
        self.assertEqual("running", result["final_status"])
        self.assertEqual(6, result["delay_seconds"])
        self.assertEqual(expected_receipt["metadata_path"], result["metadata_path"])

    def test_matching_inflight_job_reuses_same_target_across_source_worktrees(self) -> None:
        canonical = Path("/home/alex/repos/grabowski")
        first_repo = Path("/home/alex/repos/.grabowski-worktrees/deploy-first")
        second_repo = Path("/home/alex/repos/.grabowski-worktrees/deploy-second")
        head = "a" * 40
        first_command = SELF_DEPLOY._deploy_command(
            first_repo,
            first_repo / "tools/run_scheduled_deploy.py",
            head,
            6,
            canonical_repository=canonical,
            source_kind="detached-worktree",
            source_identity_sha256="1" * 64,
        )
        desired = SELF_DEPLOY._deploy_command(
            second_repo,
            second_repo / "tools/run_scheduled_deploy.py",
            head,
            8,
            canonical_repository=canonical,
            source_kind="detached-worktree",
            source_identity_sha256="2" * 64,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": first_command,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(first_command),
                "cwd": str(first_repo),
                "expected_receipt": {
                    "unit": job_dir.name,
                    "metadata_path": str(job_dir / "metadata.json"),
                    "stdout_path": str(job_dir / "stdout.log"),
                    "stderr_path": str(job_dir / "stderr.log"),
                    "status_tool": "grabowski_job_status",
                    "logs_tool": "grabowski_job_logs",
                },
            }
            with patch.object(
                SELF_DEPLOY.operator, "_jobs_root", return_value=root
            ), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator,
                "grabowski_job_status",
                return_value={"final_status": "running"},
            ):
                result = SELF_DEPLOY._matching_inflight_deploy_job(desired, second_repo)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(job_dir.name, result["unit"])
        self.assertEqual("1" * 64, result["source_identity_sha256"])

    def test_terminal_midcutover_resume_is_pruned_before_normal_deploy(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        desired = SELF_DEPLOY._deploy_command(
            repo,
            repo / "tools/run_scheduled_deploy.py",
            "b" * 40,
            8,
        )
        resume = SELF_DEPLOY._midcutover_resume_command(
            repo,
            repo / "tools/run_midcutover_resume.py",
            "a" * 40,
            "bgc-terminal-resume",
            "1" * 64,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": resume,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(resume),
                "cwd": str(repo),
            }
            with patch.object(
                SELF_DEPLOY.operator, "_jobs_root", return_value=root
            ), patch.object(
                SELF_DEPLOY, "_deploy_index", return_value={
                    "units": [job_dir.name], "pending_unit": None
                }
            ), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator,
                "grabowski_job_status",
                return_value={"final_status": "succeeded"},
            ), patch.object(SELF_DEPLOY, "_write_deploy_index") as write_index:
                self.assertIsNone(
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)
                )
        write_index.assert_called_once_with(root, units=[], pending_unit=None)

    def test_running_midcutover_resume_blocks_normal_deploy(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        desired = SELF_DEPLOY._deploy_command(
            repo,
            repo / "tools/run_scheduled_deploy.py",
            "b" * 40,
            8,
        )
        resume = SELF_DEPLOY._midcutover_resume_command(
            repo,
            repo / "tools/run_midcutover_resume.py",
            "a" * 40,
            "bgc-running-resume",
            "1" * 64,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": resume,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(resume),
                "cwd": str(repo),
            }
            with patch.object(
                SELF_DEPLOY.operator, "_jobs_root", return_value=root
            ), patch.object(
                SELF_DEPLOY, "_deploy_index", return_value={
                    "units": [job_dir.name], "pending_unit": None
                }
            ), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator,
                "grabowski_job_status",
                return_value={"final_status": "running"},
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "mid-cutover resume job is still running"
                ):
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_matching_job_with_unclear_outcome_blocks_duplicate(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        command = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": command,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(command),
                "cwd": str(repo),
                "expected_receipt": {
                    "unit": job_dir.name,
                    "metadata_path": str(job_dir / "metadata.json"),
                    "stdout_path": str(job_dir / "stdout.log"),
                    "stderr_path": str(job_dir / "stderr.log"),
                    "status_tool": "grabowski_job_status",
                    "logs_tool": "grabowski_job_logs",
                },
            }
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root, create=True), patch.object(
                SELF_DEPLOY.operator, "JOB_PREFIX", "grabowski-job-", create=True
            ), patch.object(
                SELF_DEPLOY.operator,
                "_read_job_metadata",
                return_value=metadata,
                create=True,
            ), patch.object(
                SELF_DEPLOY.operator,
                "grabowski_job_status",
                return_value={"final_status": "missing_finalization_evidence", "metadata": {}},
                create=True,
            ):
                with self.assertRaisesRegex(RuntimeError, "uncertain non-reusable outcome"):
                    SELF_DEPLOY._matching_inflight_deploy_job(command, repo)

    def test_missing_finalization_success_is_pruned_when_runtime_proves_exact_head(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        previous = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        desired = SELF_DEPLOY._deploy_command(repo, runner, "b" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": previous,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(previous),
                "cwd": str(repo),
            }
            status = {
                "final_status": "missing_finalization_evidence",
                "finalization_receipt": {"valid": False, "state": "missing_receipt"},
                "properties": {
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "Result": "success",
                    "ExecMainStatus": "0",
                },
            }
            deployment = {
                "completion_status": "complete",
                "repo_head": "a" * 40,
                "manifest_parse_valid": True,
                "manifest_schema_valid": True,
                "release_path_valid": True,
                "release_id_valid": True,
                "repo_head_valid": True,
                "stable_runtime_manifest_valid": True,
                "runtime_pointer_valid": True,
                "artifact_integrity_valid": True,
                "runtime_asset_identity_valid": True,
                "release_python_identity_valid": True,
                "environment_compatibility_valid": True,
            }
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY, "_deploy_index", return_value={"units": [job_dir.name], "pending_unit": None}
            ), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value=status
            ), patch.object(
                SELF_DEPLOY.base, "_deployment_metadata", return_value=deployment, create=True
            ), patch.object(
                SELF_DEPLOY, "_sidecars_match_deploy_head", return_value=True
            ), patch.object(SELF_DEPLOY, "_write_deploy_index") as write_index:
                self.assertIsNone(SELF_DEPLOY._matching_inflight_deploy_job(desired, repo))
        write_index.assert_called_once_with(root, units=[], pending_unit=None)

    def test_missing_finalization_success_blocks_when_runtime_head_mismatches(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        previous = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        desired = SELF_DEPLOY._deploy_command(repo, runner, "b" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": previous,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(previous),
                "cwd": str(repo),
            }
            status = {
                "final_status": "missing_finalization_evidence",
                "finalization_receipt": {"valid": False, "state": "missing_receipt"},
                "properties": {
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "Result": "success",
                    "ExecMainStatus": "0",
                },
            }
            deployment = {
                "completion_status": "complete",
                "repo_head": "c" * 40,
                "manifest_parse_valid": True,
                "manifest_schema_valid": True,
                "release_path_valid": True,
                "release_id_valid": True,
                "repo_head_valid": True,
                "stable_runtime_manifest_valid": True,
                "runtime_pointer_valid": True,
                "artifact_integrity_valid": True,
                "runtime_asset_identity_valid": True,
                "release_python_identity_valid": True,
                "environment_compatibility_valid": True,
            }
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY, "_deploy_index", return_value={"units": [job_dir.name], "pending_unit": None}
            ), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value=status
            ), patch.object(
                SELF_DEPLOY.base, "_deployment_metadata", return_value=deployment, create=True
            ):
                with self.assertRaisesRegex(RuntimeError, "uncertain non-reusable outcome"):
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_missing_finalization_runtime_match_still_requires_sidecar_readback(self) -> None:
        status = {
            "final_status": "missing_finalization_evidence",
            "finalization_receipt": {"valid": False, "state": "missing_receipt"},
            "properties": {
                "ActiveState": "inactive",
                "SubState": "dead",
                "Result": "success",
                "ExecMainStatus": "0",
            },
        }
        deployment = {
            "completion_status": "complete",
            "repo_head": "a" * 40,
            "manifest_parse_valid": True,
            "manifest_schema_valid": True,
            "release_path_valid": True,
            "release_id_valid": True,
            "repo_head_valid": True,
            "stable_runtime_manifest_valid": True,
            "runtime_pointer_valid": True,
            "artifact_integrity_valid": True,
            "runtime_asset_identity_valid": True,
            "release_python_identity_valid": True,
            "environment_compatibility_valid": True,
        }
        command_fields = {
            "source_kind": "canonical-main",
            "canonical_repository": "/home/alex/repos/grabowski",
            "expected_head": "a" * 40,
        }
        with patch.object(
            SELF_DEPLOY.base, "_deployment_metadata", return_value=deployment, create=True
        ), patch.object(
            SELF_DEPLOY, "_sidecars_match_deploy_head", return_value=False
        ):
            self.assertFalse(
                SELF_DEPLOY._missing_finalization_deploy_is_runtime_proven(
                    status, command_fields
                )
            )

    def test_sidecar_readback_is_exact_head_and_runtime_catalog_bound(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        marker = 'runtime_python="$HOME/.local/share/grabowski-mcp/.venv/bin/python"'
        router_template = f"#!/bin/sh\n{marker}\n".encode("utf-8")
        expected_router = (
            f"#!/bin/sh\nruntime_python={SELF_DEPLOY.SIDECAR_RUNTIME_PYTHON}\n".encode("utf-8")
        )
        scheduler = b"#!/usr/bin/env python3\nprint('scheduler')\n"
        router_sha256 = hashlib.sha256(expected_router).hexdigest()
        runtime = {
            "valid": True,
            "catalog_source": "deployment_catalog",
            "catalog_sha256": "c" * 64,
        }
        recommendation = {
            "catalog_sha256": "c" * 64,
            "decision": "controller",
            "controller": "grabowski-primary",
            "primary_role": "controller-integrator",
            "delegated_scoped_writers_allowed": True,
            "controller_integration_required": True,
            "single_mutating_writer": True,
            "single_mutating_writer_scope": "overlapping-resource-lane",
            "external_primary_writer_forbidden": False,
            "automatic_execution_authorized": True,
        }
        fields = {
            "source_kind": "canonical-main",
            "canonical_repository": str(repo),
            "expected_head": "a" * 40,
        }
        with patch.object(
            SELF_DEPLOY, "_sidecar_git_blob", side_effect=[router_template, scheduler]
        ), patch.object(
            SELF_DEPLOY,
            "_sidecar_file_bytes",
            side_effect=[
                expected_router,
                scheduler,
                f"{router_sha256}\n".encode("ascii"),
            ],
        ), patch.object(
            SELF_DEPLOY, "_sidecar_json_readback", side_effect=[runtime, recommendation]
        ):
            self.assertTrue(SELF_DEPLOY._sidecars_match_deploy_head(fields))

        with patch.object(
            SELF_DEPLOY, "_sidecar_git_blob", side_effect=[router_template, scheduler]
        ), patch.object(
            SELF_DEPLOY,
            "_sidecar_file_bytes",
            side_effect=[
                expected_router,
                b"#!/usr/bin/env python3\n# drifted\n",
                f"{router_sha256}\n".encode("ascii"),
            ],
        ), patch.object(SELF_DEPLOY, "_sidecar_json_readback") as readback:
            self.assertFalse(SELF_DEPLOY._sidecars_match_deploy_head(fields))
            readback.assert_not_called()

    def test_invalid_finalization_evidence_blocks_even_when_runtime_head_matches(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        previous = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        desired = SELF_DEPLOY._deploy_command(repo, runner, "b" * 40, 8)
        deployment = {
            "completion_status": "complete",
            "repo_head": "a" * 40,
            "manifest_parse_valid": True,
            "manifest_schema_valid": True,
            "release_path_valid": True,
            "release_id_valid": True,
            "repo_head_valid": True,
            "stable_runtime_manifest_valid": True,
            "runtime_pointer_valid": True,
            "artifact_integrity_valid": True,
            "runtime_asset_identity_valid": True,
            "release_python_identity_valid": True,
            "environment_compatibility_valid": True,
        }
        for finalization_state in ("invalid_contract", "invalid_receipt"):
            with self.subTest(finalization_state=finalization_state), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                job_dir = root / "grabowski-job-abcdef012345"
                job_dir.mkdir()
                metadata = {
                    "argv": previous,
                    "argv_sha256": SELF_DEPLOY.operator._argv_hash(previous),
                    "cwd": str(repo),
                }
                status = {
                    "final_status": "missing_finalization_evidence",
                    "finalization_receipt": {"valid": False, "state": finalization_state},
                    "properties": {
                        "ActiveState": "inactive",
                        "SubState": "dead",
                        "Result": "success",
                        "ExecMainStatus": "0",
                    },
                }
                with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                    SELF_DEPLOY, "_deploy_index", return_value={"units": [job_dir.name], "pending_unit": None}
                ), patch.object(
                    SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
                ), patch.object(
                    SELF_DEPLOY.operator, "grabowski_job_status", return_value=status
                ), patch.object(
                    SELF_DEPLOY.base, "_deployment_metadata", return_value=deployment, create=True
                ):
                    with self.assertRaisesRegex(RuntimeError, "uncertain non-reusable outcome"):
                        SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_inflight_evidence_prunes_runtime_proven_missing_finalization(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        previous = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": previous,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(previous),
                "cwd": str(repo),
            }
            status = {
                "final_status": "missing_finalization_evidence",
                "finalization_receipt": {"valid": False, "state": "missing_receipt"},
                "properties": {
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "Result": "success",
                    "ExecMainStatus": "0",
                },
            }
            deployment = {
                "completion_status": "complete",
                "repo_head": "a" * 40,
                "manifest_parse_valid": True,
                "manifest_schema_valid": True,
                "release_path_valid": True,
                "release_id_valid": True,
                "repo_head_valid": True,
                "stable_runtime_manifest_valid": True,
                "runtime_pointer_valid": True,
                "artifact_integrity_valid": True,
                "runtime_asset_identity_valid": True,
                "release_python_identity_valid": True,
                "environment_compatibility_valid": True,
            }
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY, "_deploy_index", return_value={"units": [job_dir.name], "pending_unit": None}
            ), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value=status
            ), patch.object(
                SELF_DEPLOY.base, "_deployment_metadata", return_value=deployment, create=True
            ), patch.object(
                SELF_DEPLOY, "_sidecars_match_deploy_head", return_value=True
            ), patch.object(SELF_DEPLOY, "_write_deploy_index") as write_index:
                evidence = SELF_DEPLOY.inflight_runtime_job_evidence(prune=True)
        self.assertEqual([job_dir.name], evidence["pruned_units"])
        self.assertEqual([], evidence["blocking_units"])
        write_index.assert_called_once_with(root, units=[], pending_unit=None)

    def test_matching_deploy_blocks_durable_outcome_unknown_before_retry(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        command = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": command,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(command),
                "cwd": str(repo),
                "expected_receipt": {
                    "unit": job_dir.name,
                    "metadata_path": str(job_dir / "metadata.json"),
                    "stdout_path": str(job_dir / "stdout.log"),
                    "stderr_path": str(job_dir / "stderr.log"),
                    "status_tool": "grabowski_job_status",
                    "logs_tool": "grabowski_job_logs",
                },
            }
            status = {
                "final_status": "failed",
                "finalization_receipt": {
                    "valid": True,
                    "final_status": "outcome_unknown",
                    "blind_retry_allowed": False,
                },
            }
            with patch.object(
                SELF_DEPLOY.operator, "_jobs_root", return_value=root
            ), patch.object(
                SELF_DEPLOY,
                "_deploy_index",
                return_value={"units": [job_dir.name], "pending_unit": None},
            ), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value=status
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "authoritative runtime readback before retry"
                ):
                    SELF_DEPLOY._matching_inflight_deploy_job(command, repo)

    def _job_fixture(self, root: Path, repo: Path, runner: Path, head: str, *, delay: int = 8) -> tuple[Path, list[str], dict[str, object]]:
        job_dir = root / "grabowski-job-abcdef012345"
        job_dir.mkdir()
        command = SELF_DEPLOY._deploy_command(repo, runner, head, delay)
        metadata = {
            "argv": command,
            "argv_sha256": SELF_DEPLOY.operator._argv_hash(command),
            "cwd": str(repo),
            "expected_receipt": {
                "unit": job_dir.name,
                "metadata_path": str(job_dir / "metadata.json"),
                "stdout_path": str(job_dir / "stdout.log"),
                "stderr_path": str(job_dir / "stderr.log"),
                "status_tool": "grabowski_job_status",
                "logs_tool": "grabowski_job_logs",
            },
        }
        return job_dir, command, metadata

    def test_malformed_durable_job_argv_blocks_scan(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        malformed_values = ("not-a-list", ["/usr/bin/python3", 7])
        for malformed in malformed_values:
            with self.subTest(argv=malformed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                unit = "grabowski-job-abcdef012345"
                (root / unit).mkdir()
                with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                    SELF_DEPLOY.operator,
                    "_read_job_metadata",
                    return_value={"unit": unit, "argv": malformed},
                ):
                    with self.assertRaisesRegex(RuntimeError, "durable job argv is malformed"):
                        SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_unreadable_regular_job_metadata_blocks_scan(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        command = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "grabowski-job-abcdef012345").mkdir()
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", side_effect=ValueError("broken")
            ):
                with self.assertRaisesRegex(RuntimeError, "metadata is unreadable"):
                    SELF_DEPLOY._matching_inflight_deploy_job(command, repo)

    def test_exact_durable_job_symlink_blocks_scan(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            (root / "grabowski-job-abcdef012345").symlink_to(target, target_is_directory=True)
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "not a real directory"):
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_exact_durable_job_regular_file_blocks_scan(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "grabowski-job-abcdef012345").write_text("invalid", encoding="utf-8")
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "not a real directory"):
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_nonstandard_legacy_job_directory_is_ignored(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        command = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "grabowski-job-legacy-name").mkdir()
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata"
            ) as read_metadata:
                self.assertIsNone(SELF_DEPLOY._matching_inflight_deploy_job(command, repo))
            read_metadata.assert_not_called()

    def test_running_deploy_for_different_head_blocks(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, metadata = self._job_fixture(root, repo, runner, "b" * 40)
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value={"final_status": "running"}
            ):
                with self.assertRaisesRegex(RuntimeError, "different head"):
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_multiple_identical_running_deploys_block(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, _, first_metadata = self._job_fixture(root, repo, runner, "a" * 40)
            second = root / "grabowski-job-fedcba543210"
            second.mkdir()
            second_metadata = dict(first_metadata)
            second_metadata["expected_receipt"] = {
                **first_metadata["expected_receipt"],
                "unit": second.name,
                "metadata_path": str(second / "metadata.json"),
                "stdout_path": str(second / "stdout.log"),
                "stderr_path": str(second / "stderr.log"),
            }
            metadata_by_unit = {first.name: first_metadata, second.name: second_metadata}
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", side_effect=lambda unit: metadata_by_unit[unit]
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value={"final_status": "running"}
            ):
                with self.assertRaisesRegex(RuntimeError, "multiple identical"):
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_tampered_command_hash_or_receipt_path_blocks(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, metadata = self._job_fixture(root, repo, runner, "a" * 40)
            metadata["argv_sha256"] = "0" * 64
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ):
                with self.assertRaisesRegex(RuntimeError, "command hash mismatch"):
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)
            metadata["argv_sha256"] = SELF_DEPLOY.operator._argv_hash(metadata["argv"])
            metadata["expected_receipt"]["stdout_path"] = "/other/stdout.log"
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value={"final_status": "running"}
            ):
                with self.assertRaisesRegex(RuntimeError, "not bound"):
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_terminal_legacy_job_without_receipt_allows_retry(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": desired,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(desired),
                "cwd": str(repo),
            }
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value={"final_status": "succeeded"}
            ):
                self.assertIsNone(SELF_DEPLOY._matching_inflight_deploy_job(desired, repo))

    def test_unclear_legacy_job_for_different_head_blocks(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        other = SELF_DEPLOY._deploy_command(repo, runner, "b" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job_dir = root / "grabowski-job-abcdef012345"
            job_dir.mkdir()
            metadata = {
                "argv": other,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(other),
                "cwd": str(repo),
            }
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value={"final_status": "missing_finalization_evidence"}
            ):
                with self.assertRaisesRegex(RuntimeError, "uncertain non-reusable outcome"):
                    SELF_DEPLOY._matching_inflight_deploy_job(desired, repo)

    def test_completed_finalized_job_allows_retry(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, metadata = self._job_fixture(root, repo, runner, "a" * 40)
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value={"final_status": "completed"}
            ):
                self.assertIsNone(SELF_DEPLOY._matching_inflight_deploy_job(desired, repo))

    def test_launch_failed_job_allows_retry(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        desired = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, metadata = self._job_fixture(root, repo, runner, "a" * 40)
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ), patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value={"final_status": "launch_failed"}
            ):
                self.assertIsNone(SELF_DEPLOY._matching_inflight_deploy_job(desired, repo))

    def test_deploy_command_hash_uses_operator_hash_contract(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        command = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        self.assertEqual(
            SELF_DEPLOY.operator._argv_hash(command),
            SELF_DEPLOY._deploy_command_sha256(command),
        )

    def test_non_job_entries_do_not_consume_scan_bound(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        command = SELF_DEPLOY._deploy_command(repo, runner, "a" * 40, 8)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "unrelated-a").mkdir()
            (root / "unrelated-b").mkdir()
            with patch.object(SELF_DEPLOY.operator, "_jobs_root", return_value=root), patch.object(
                SELF_DEPLOY, "MAX_JOB_SCAN_ENTRIES", 1
            ):
                self.assertIsNone(SELF_DEPLOY._matching_inflight_deploy_job(command, repo))

    def test_schedule_lock_times_out_instead_of_hanging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "lock"
            with patch.object(SELF_DEPLOY, "DEPLOY_SCHEDULE_LOCK", lock), patch.object(
                SELF_DEPLOY, "DEPLOY_SCHEDULE_LOCK_TIMEOUT_SECONDS", 10.0
            ), patch.object(
                SELF_DEPLOY.fcntl, "flock", side_effect=BlockingIOError
            ), patch.object(
                SELF_DEPLOY.time, "monotonic", side_effect=[0.0, 11.0]
            ), patch.object(SELF_DEPLOY.time, "sleep"):
                with self.assertRaisesRegex(TimeoutError, "lock acquisition timed out"):
                    with SELF_DEPLOY._deploy_schedule_lock():
                        pass

    def test_schedule_lock_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("", encoding="utf-8")
            lock = root / "lock"
            lock.symlink_to(target)
            with patch.object(SELF_DEPLOY, "DEPLOY_SCHEDULE_LOCK", lock):
                with self.assertRaisesRegex(PermissionError, "may not be a symlink"):
                    with SELF_DEPLOY._deploy_schedule_lock():
                        pass


class ScheduledDeployRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.productive_blue_green = patch.object(
            RUNNER,
            "run_productive_blue_green",
            return_value=_productive_blue_green_result(),
        )
        self.productive_blue_green_mock = self.productive_blue_green.start()
        self.addCleanup(self.productive_blue_green.stop)

    def test_capture_fails_closed_on_excess_output(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "exceeded"):
            RUNNER.run_capture(
                [sys.executable, "-c", 'print("x" * 70000)'],
                cwd=Path("/tmp"),
            )

    def test_child_environment_strips_job_finalization_bindings(self) -> None:
        bindings = {name: f"value-{index}" for index, name in enumerate(RUNNER.FINALIZATION_ENV.values())}
        with patch.dict(os.environ, {**bindings, "GRABOWSKI_UNRELATED": "preserved"}, clear=False):
            environment = RUNNER.child_environment()
        for name in bindings:
            self.assertNotIn(name, environment)
        self.assertEqual(environment["GRABOWSKI_UNRELATED"], "preserved")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")

    def test_run_streamed_uses_sanitized_child_environment(self) -> None:
        process = Mock()
        process.wait.return_value = 0
        bindings = {name: "secret-binding" for name in RUNNER.FINALIZATION_ENV.values()}
        with patch.dict(os.environ, bindings, clear=False), patch.object(
            RUNNER.subprocess, "Popen", return_value=process
        ) as popen:
            RUNNER.run_streamed(
                ["make", "validate"],
                cwd=Path("/tmp"),
                timeout_seconds=30,
                phase="validate",
            )
        environment = popen.call_args.kwargs["env"]
        for name in bindings:
            self.assertNotIn(name, environment)

    def test_sidecar_reconciliation_applies_checks_and_hash_binds_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            installer = repo / RUNNER.SIDECAR_INSTALLER_RELATIVE_PATH
            installer.parent.mkdir(parents=True)
            installer.write_text("pass\n", encoding="utf-8")
            live = {
                "release_id": "r",
                "repo_head": "f" * 40,
                "completion_status": "complete",
            }
            with patch.object(
                RUNNER,
                "_json_command",
                side_effect=[_sidecar_apply_receipt(), _sidecar_check_receipt()],
            ) as command:
                result = RUNNER.reconcile_coding_agent_sidecars(repo, live)
        self.assertEqual(result, _sidecar_reconciliation())
        self.assertEqual(command.call_count, 2)
        self.assertEqual(command.call_args_list[0].args[0][-1], "--apply")
        self.assertEqual(command.call_args_list[1].args[0][-1], "--check")
        self.assertEqual(command.call_args_list[0].kwargs["cwd"], repo)
        self.assertEqual(command.call_args_list[1].kwargs["cwd"], repo)

    def test_sidecar_reconciliation_rejects_apply_check_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            installer = repo / RUNNER.SIDECAR_INSTALLER_RELATIVE_PATH
            installer.parent.mkdir(parents=True)
            installer.write_text("pass\n", encoding="utf-8")
            checked = _sidecar_check_receipt()
            checked["scheduler_sha256"] = "d" * 64
            with patch.object(
                RUNNER,
                "_json_command",
                side_effect=[_sidecar_apply_receipt(), checked],
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "apply and check identities differ"
                ):
                    RUNNER.reconcile_coding_agent_sidecars(
                        repo,
                        {"release_id": "r", "repo_head": "f" * 40},
                    )

    def test_sidecar_reconciliation_rejects_controller_contract_regressions(
        self,
    ) -> None:
        live = {"release_id": "r", "repo_head": "f" * 40}
        regressions = {
            "direct-writer role": {"primary_role": "direct-writer"},
            "external writer prohibition true": {
                "external_primary_writer_forbidden": True
            },
            "automatic false": {"automatic_execution_authorized": False},
            "missing delegated writers": {
                "delegated_scoped_writers_allowed": False
            },
            "missing controller integration": {
                "controller_integration_required": False
            },
            "missing single writer": {"single_mutating_writer": False},
            "wrong writer scope": {
                "single_mutating_writer_scope": "whole-repository"
            },
            "catalog mismatch": {"catalog_sha256": "d" * 64},
        }
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            installer = repo / RUNNER.SIDECAR_INSTALLER_RELATIVE_PATH
            installer.parent.mkdir(parents=True)
            installer.write_text("pass\n", encoding="utf-8")
            for label, override in regressions.items():
                with self.subTest(surface="apply-readback", label=label):
                    applied = _sidecar_apply_receipt()
                    applied["readback"] = {
                        **applied["readback"],
                        **override,
                    }
                    if "automatic_execution_authorized" in override:
                        applied["automatic_execution_authorized"] = override[
                            "automatic_execution_authorized"
                        ]
                    with patch.object(
                        RUNNER,
                        "_json_command",
                        side_effect=[applied, _sidecar_check_receipt()],
                    ):
                        with self.assertRaisesRegex(
                            RuntimeError, "sidecar apply"
                        ):
                            RUNNER.reconcile_coding_agent_sidecars(repo, live)
                with self.subTest(surface="check", label=label):
                    checked = {**_sidecar_check_receipt(), **override}
                    with patch.object(
                        RUNNER,
                        "_json_command",
                        side_effect=[_sidecar_apply_receipt(), checked],
                    ):
                        with self.assertRaisesRegex(
                            RuntimeError, "sidecar post-install check"
                        ):
                            RUNNER.reconcile_coding_agent_sidecars(repo, live)

    def test_json_sidecar_command_strips_job_finalization_bindings(self) -> None:
        bindings = {
            name: "secret-binding" for name in RUNNER.FINALIZATION_ENV.values()
        }
        with patch.dict(os.environ, bindings, clear=False), patch.object(
            RUNNER,
            "run_capture",
            return_value=json.dumps(_sidecar_check_receipt()),
        ) as capture:
            value = RUNNER._json_command(
                [sys.executable, "installer", "--check"],
                cwd=Path("/tmp"),
            )
        self.assertTrue(value["installed"])
        environment = capture.call_args.kwargs["environment"]
        for name in bindings:
            self.assertNotIn(name, environment)

    def test_repoground_managed_source_guard_rejects_direct_and_symlink_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            managed_root = root / ".repoground-sources"
            managed_repo = managed_root / "heimgewebe__grabowski__main"
            managed_repo.mkdir(parents=True)
            alias = root / "alias"
            alias.symlink_to(managed_repo, target_is_directory=True)
            allowed = root / ".grabowski-worktrees" / "deploy"
            allowed.mkdir(parents=True)
            with patch.object(
                RUNNER, "REPOGROUND_MANAGED_SOURCE_ROOT", managed_root
            ), patch.dict(
                os.environ, {"REPOGROUND_SOURCE_ROOT": str(root / "configured-root")}
            ):
                with self.assertRaisesRegex(RuntimeError, "RepoGround-managed"):
                    RUNNER.assert_not_repoground_managed_source(managed_repo)
                with self.assertRaisesRegex(RuntimeError, "RepoGround-managed"):
                    RUNNER.assert_not_repoground_managed_source(alias)
                RUNNER.assert_not_repoground_managed_source(allowed)
                self.assertIn(
                    managed_root.resolve(),
                    RUNNER.repoground_managed_source_roots(),
                )
                self.assertIn(
                    (root / "configured-root").resolve(),
                    RUNNER.repoground_managed_source_roots(),
                )

    def test_runner_rejects_repoground_managed_source_before_delay_or_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            managed_root = root / ".repoground-sources"
            repo = managed_root / "heimgewebe__grabowski__main"
            repo.mkdir(parents=True)
            expected = "f" * 40
            argv = [
                "runner",
                "--repo",
                str(repo),
                "--canonical-repo",
                str(root / "canonical"),
                "--source-kind",
                "detached-worktree",
                "--source-identity-sha256",
                "0" * 64,
                "--expected-head",
                expected,
                "--delay-seconds",
                "5",
            ]
            with patch.object(
                RUNNER, "REPOGROUND_MANAGED_SOURCE_ROOT", managed_root
            ), patch.dict(
                os.environ, {"REPOGROUND_SOURCE_ROOT": str(root / "configured-root")}
            ), patch.object(sys, "argv", argv), patch.object(
                RUNNER, "load_finalization_binding", return_value=None
            ), patch.object(RUNNER.time, "sleep") as sleep, patch.object(
                RUNNER, "verify_repository"
            ) as verify, patch.object(RUNNER, "run_streamed") as streamed:
                self.assertEqual(RUNNER.main(), 1)
            sleep.assert_not_called()
            verify.assert_not_called()
            streamed.assert_not_called()

    def test_verify_repository_accepts_detached_shared_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            canonical = root / "canonical"
            source = root / "source"
            canonical.mkdir()
            source.mkdir()
            common = canonical / ".git"
            common.mkdir()
            expected = "d" * 40
            with patch.object(
                RUNNER,
                "run_capture",
                side_effect=[
                    str(common),
                    str(common),
                    expected,
                    "HEAD",
                    expected,
                    "",
                ],
            ):
                RUNNER.verify_repository(
                    source,
                    canonical,
                    "detached-worktree",
                    expected,
                )

    def test_verify_repository_rejects_non_main(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            (repo / ".git").mkdir()
            expected = "e" * 40
            with patch.object(
                RUNNER,
                "run_capture",
                side_effect=[".git", expected, "topic", expected, ""],
            ):
                with self.assertRaisesRegex(RuntimeError, "invalid branch state"):
                    RUNNER.verify_repository(repo, repo, "canonical-main", expected)

    def test_dispatcher_contention_observation_accepts_two_stable_idle_samples(self) -> None:
        metrics = _dispatcher_metrics()
        with patch.object(
            RUNNER.deploy_dual.core, "http_text", side_effect=["one", "two"]
        ), patch.object(
            RUNNER.deploy_dual,
            "_parse_tunnel_drain_metrics",
            side_effect=[metrics.copy(), metrics.copy()],
        ), patch.object(RUNNER.time, "sleep") as sleep:
            observed = RUNNER.observe_tunnel_dispatcher_contention()
        self.assertEqual(observed["state"], "idle")
        self.assertEqual(observed["reason"], "two-stable-idle-samples")
        self.assertEqual(len(observed["samples"]), 2)
        sleep.assert_called_once_with(
            RUNNER.EARLY_DISPATCHER_SAMPLE_INTERVAL_SECONDS
        )

    def test_dispatcher_contention_observation_accepts_idle_warm_workers(self) -> None:
        metrics = _dispatcher_metrics(workers=9.0)
        with (
            patch.object(
                RUNNER.deploy_dual.core, "http_text", side_effect=["one", "two"]
            ),
            patch.object(
                RUNNER.deploy_dual,
                "_parse_tunnel_drain_metrics",
                side_effect=[metrics.copy(), metrics.copy()],
            ),
            patch.object(RUNNER.time, "sleep"),
        ):
            observed = RUNNER.observe_tunnel_dispatcher_contention()
        self.assertEqual(observed["state"], "idle")
        self.assertEqual(observed["reason"], "two-stable-idle-samples")
        self.assertEqual(
            observed["samples"][0]["metrics"]["dispatcher_worker_pool_occupancy"],
            9.0,
        )


    def test_dispatcher_contention_observation_detects_unfinished_command_with_zero_workers(
        self,
    ) -> None:
        metrics = _dispatcher_metrics(
            workers=0.0, polled=8.0, enqueued=8.0, responses=7.0
        )
        with (
            patch.object(
                RUNNER.deploy_dual.core, "http_text", side_effect=["one", "two"]
            ),
            patch.object(
                RUNNER.deploy_dual,
                "_parse_tunnel_drain_metrics",
                side_effect=[metrics.copy(), metrics.copy()],
            ),
            patch.object(RUNNER.time, "sleep"),
        ):
            observed = RUNNER.observe_tunnel_dispatcher_contention()
        self.assertEqual(observed["state"], "busy")
        self.assertEqual(observed["reason"], "dispatcher-work-observed")
        self.assertEqual(
            observed["busy_samples"][0]["mismatch"]["commands_final_responses_total"],
            7.0,
        )



    def test_dispatcher_contention_observation_fails_closed_on_generation_drift(self) -> None:
        with patch.object(
            RUNNER.deploy_dual.core, "http_text", side_effect=["one", "two"]
        ), patch.object(
            RUNNER.deploy_dual,
            "_parse_tunnel_drain_metrics",
            side_effect=[
                _dispatcher_metrics(process_start=100.0),
                _dispatcher_metrics(process_start=101.0),
            ],
        ), patch.object(RUNNER.time, "sleep"):
            observed = RUNNER.observe_tunnel_dispatcher_contention()
        self.assertEqual(observed["state"], "unknown")
        self.assertEqual(observed["reason"], "dispatcher-generation-drift")

    def test_dispatcher_contention_observation_fails_closed_on_counter_regression(self) -> None:
        with patch.object(
            RUNNER.deploy_dual.core, "http_text", side_effect=["one", "two"]
        ), patch.object(
            RUNNER.deploy_dual,
            "_parse_tunnel_drain_metrics",
            side_effect=[
                _dispatcher_metrics(polled=8.0, enqueued=8.0, responses=8.0),
                _dispatcher_metrics(polled=7.0, enqueued=7.0, responses=7.0),
            ],
        ), patch.object(RUNNER.time, "sleep"):
            observed = RUNNER.observe_tunnel_dispatcher_contention()
        self.assertEqual(observed["state"], "unknown")
        self.assertEqual(observed["reason"], "dispatcher-counter-regression")
        self.assertIn("commands_polled_total", observed["regressed_counters"])

    def test_dispatcher_contention_observation_detects_completed_activity_between_samples(self) -> None:
        with patch.object(
            RUNNER.deploy_dual.core, "http_text", side_effect=["one", "two"]
        ), patch.object(
            RUNNER.deploy_dual,
            "_parse_tunnel_drain_metrics",
            side_effect=[
                _dispatcher_metrics(polled=7.0, enqueued=7.0, responses=7.0),
                _dispatcher_metrics(polled=8.0, enqueued=8.0, responses=8.0),
            ],
        ), patch.object(RUNNER.time, "sleep"):
            observed = RUNNER.observe_tunnel_dispatcher_contention()
        self.assertEqual(observed["state"], "busy")
        self.assertEqual(observed["reason"], "dispatcher-activity-between-samples")

    def test_dispatcher_contention_observation_fails_closed_without_metrics(self) -> None:
        with patch.object(RUNNER.deploy_dual.core, "http_text", return_value=None):
            observed = RUNNER.observe_tunnel_dispatcher_contention()
        self.assertEqual(observed["state"], "unknown")
        self.assertEqual(observed["reason"], "metrics-unavailable")

    def test_contention_preflight_is_hash_bound_and_preserves_final_gates(self) -> None:
        lock = {"state": "available", "observed_at_unix_ns": 1}
        dispatcher = {"state": "idle", "observed_at_unix_ns": 2}
        with patch.object(
            RUNNER.deploy_core,
            "observe_deployment_lock_availability",
            return_value=lock,
        ), patch.object(
            RUNNER, "observe_tunnel_dispatcher_contention", return_value=dispatcher
        ), patch.object(RUNNER.time, "time_ns", return_value=3):
            result = RUNNER.deployment_contention_preflight(
                expected_head="a" * 40,
                source_identity_sha256="b" * 64,
            )
        material = {
            key: value for key, value in result.items() if key != "evidence_sha256"
        }
        self.assertEqual(
            result["evidence_sha256"], RUNNER.canonical_json_sha256(material)
        )
        self.assertEqual(result["decision"], "proceed")
        self.assertFalse(result["validation_started"])
        self.assertTrue(result["final_lock_and_drain_gates_required"])

    def test_contention_preflight_keeps_failed_dispatcher_probe_advisory(self) -> None:
        with (
            patch.object(
                RUNNER.deploy_core,
                "observe_deployment_lock_availability",
                return_value={"state": "available"},
            ),
            patch.object(
                RUNNER,
                "observe_tunnel_dispatcher_contention",
                side_effect=RuntimeError("probe failed"),
            ),
        ):
            result = RUNNER.deployment_contention_preflight(
                expected_head="a" * 40,
                source_identity_sha256="b" * 64,
            )
        self.assertEqual("proceed", result["decision"])
        self.assertEqual("unknown", result["dispatcher"]["state"])
        self.assertEqual("advisory-probe-failed", result["dispatcher"]["reason"])


    def test_contention_preflight_does_not_let_dispatcher_traffic_starve_admission_drain(
        self,
    ) -> None:
        lock = {"state": "available", "observed_at_unix_ns": 1}
        dispatcher = {"state": "busy", "observed_at_unix_ns": 2}
        with (
            patch.object(
                RUNNER.deploy_core,
                "observe_deployment_lock_availability",
                return_value=lock,
            ),
            patch.object(
                RUNNER, "observe_tunnel_dispatcher_contention", return_value=dispatcher
            ),
            patch.object(RUNNER.time, "time_ns", return_value=3),
        ):
            result = RUNNER.deployment_contention_preflight(
                expected_head="a" * 40,
                source_identity_sha256="b" * 64,
            )
        self.assertEqual("proceed", result["decision"])
        self.assertTrue(result["dispatcher_activity_advisory_before_final_admission"])
        self.assertTrue(result["final_lock_and_drain_gates_required"])


    def _runner_argv(self, repo: Path, expected: str) -> list[str]:
        return [
            "runner",
            "--repo",
            str(repo),
            "--canonical-repo",
            str(repo),
            "--source-kind",
            "canonical-main",
            "--source-identity-sha256",
            "0" * 64,
            "--expected-head",
            expected,
            "--delay-seconds",
            "5",
        ]

    def test_main_retries_only_contention_and_then_succeeds(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        with patch.object(
            sys, "argv", self._runner_argv(repo, expected)
        ), patch.object(
            RUNNER, "load_finalization_binding", return_value=None
        ), patch.object(RUNNER.time, "sleep") as sleep, patch.object(
            RUNNER, "verify_repository"
        ) as verify, patch.object(
            RUNNER,
            "deployment_contention_preflight",
            side_effect=[
                _contention_result(decision="defer"),
                _contention_result(decision="defer"),
                _contention_result(),
            ],
        ) as preflight, patch.object(
            RUNNER, "run_streamed"
        ) as streamed, patch.object(
            RUNNER,
            "verify_live_manifest",
            return_value={
                "release_id": "r",
                "repo_head": expected,
                "completion_status": "complete",
            },
        ), patch.object(
            RUNNER,
            "reconcile_coding_agent_sidecars",
            return_value=_sidecar_reconciliation(expected),
        ):
            self.assertEqual(RUNNER.main(), 0)
        self.assertEqual(preflight.call_count, 3)
        self.assertEqual(verify.call_count, 6)
        self.assertEqual(sleep.call_args_list, [call(5), call(5), call(10)])
        streamed.assert_called_once_with(
            ["make", "validate"],
            cwd=repo,
            timeout_seconds=1200,
            phase="validate",
        )
        self.assertEqual(self.productive_blue_green_mock.call_count, 1)

    def test_main_fails_after_bounded_contention_retries(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        with patch.object(
            sys, "argv", self._runner_argv(repo, expected)
        ), patch.object(
            RUNNER, "load_finalization_binding", return_value=None
        ), patch.object(RUNNER.time, "sleep") as sleep, patch.object(
            RUNNER, "verify_repository"
        ) as verify, patch.object(
            RUNNER,
            "deployment_contention_preflight",
            return_value=_contention_result(decision="defer"),
        ) as preflight, patch.object(RUNNER, "run_streamed") as streamed:
            self.assertEqual(RUNNER.main(), 1)
        self.assertEqual(
            preflight.call_count, RUNNER.DEPLOYMENT_CONTENTION_MAX_ATTEMPTS
        )
        self.assertEqual(
            verify.call_count, RUNNER.DEPLOYMENT_CONTENTION_MAX_ATTEMPTS
        )
        self.assertEqual(
            sleep.call_args_list, [call(5), call(5), call(10), call(20)]
        )
        streamed.assert_not_called()

    def test_main_revalidates_identity_before_each_contention_retry(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        with patch.object(
            sys, "argv", self._runner_argv(repo, expected)
        ), patch.object(
            RUNNER, "load_finalization_binding", return_value=None
        ), patch.object(RUNNER.time, "sleep") as sleep, patch.object(
            RUNNER,
            "verify_repository",
            side_effect=[None, RuntimeError("HEAD drift")],
        ) as verify, patch.object(
            RUNNER,
            "deployment_contention_preflight",
            return_value=_contention_result(decision="defer"),
        ) as preflight, patch.object(RUNNER, "run_streamed") as streamed:
            self.assertEqual(RUNNER.main(), 1)
        self.assertEqual(verify.call_count, 2)
        preflight.assert_called_once()
        self.assertEqual(sleep.call_args_list, [call(5), call(5)])
        streamed.assert_not_called()

    def test_main_does_not_retry_non_contention_failure(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        with patch.object(
            sys, "argv", self._runner_argv(repo, expected)
        ), patch.object(
            RUNNER, "load_finalization_binding", return_value=None
        ), patch.object(RUNNER.time, "sleep") as sleep, patch.object(
            RUNNER, "verify_repository"
        ) as verify, patch.object(
            RUNNER,
            "deployment_contention_preflight",
            side_effect=RuntimeError("metrics probe failed"),
        ) as preflight, patch.object(RUNNER, "run_streamed") as streamed:
            self.assertEqual(RUNNER.main(), 1)
        verify.assert_called_once()
        preflight.assert_called_once()
        self.assertEqual(sleep.call_args_list, [call(5)])
        streamed.assert_not_called()

    def test_main_does_not_retry_invalid_contention_decision(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        with patch.object(
            sys, "argv", self._runner_argv(repo, expected)
        ), patch.object(
            RUNNER, "load_finalization_binding", return_value=None
        ), patch.object(RUNNER.time, "sleep") as sleep, patch.object(
            RUNNER, "verify_repository"
        ) as verify, patch.object(
            RUNNER,
            "deployment_contention_preflight",
            return_value=_contention_result(decision="unknown"),
        ) as preflight, patch.object(RUNNER, "run_streamed") as streamed:
            self.assertEqual(RUNNER.main(), 1)
        verify.assert_called_once()
        preflight.assert_called_once()
        self.assertEqual(sleep.call_args_list, [call(5)])
        streamed.assert_not_called()

    def test_main_validates_before_deploying(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        with patch.object(sys, "argv", ["runner", "--repo", str(repo), "--canonical-repo", str(repo), "--source-kind", "canonical-main", "--source-identity-sha256", "0" * 64, "--expected-head", expected, "--delay-seconds", "5"]), patch.object(RUNNER, "load_finalization_binding", return_value=None), patch.object(RUNNER.time, "sleep"), patch.object(RUNNER, "verify_repository") as verify, patch.object(RUNNER, "deployment_contention_preflight", return_value=_contention_result()), patch.object(RUNNER, "run_streamed") as streamed, patch.object(RUNNER, "verify_live_manifest", return_value={"release_id": "r", "repo_head": expected, "completion_status": "complete"}), patch.object(RUNNER, "reconcile_coding_agent_sidecars", return_value=_sidecar_reconciliation(expected)):
            self.assertEqual(RUNNER.main(), 0)
        self.assertEqual(verify.call_count, 4)
        self.assertEqual(streamed.call_args_list[0].args[0], ["make", "validate"])
        self.productive_blue_green_mock.assert_called_once_with(
            repo=repo,
            expected_head=expected,
            source_identity_sha256="0" * 64,
        )

    def test_main_rejects_source_drift_before_sidecar_install(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        with patch.object(
            sys, "argv", self._runner_argv(repo, expected)
        ), patch.object(
            RUNNER, "load_finalization_binding", return_value=None
        ), patch.object(RUNNER.time, "sleep"), patch.object(
            RUNNER,
            "verify_repository",
            side_effect=[
                None,
                None,
                RuntimeError("source drift after runtime deployment"),
            ],
        ) as verify, patch.object(
            RUNNER,
            "deployment_contention_preflight",
            return_value=_contention_result(),
        ), patch.object(RUNNER, "run_streamed") as streamed, patch.object(
            RUNNER,
            "verify_live_manifest",
            return_value={
                "release_id": "release",
                "repo_head": expected,
                "completion_status": "complete",
            },
        ), patch.object(
            RUNNER, "reconcile_coding_agent_sidecars"
        ) as reconcile:
            self.assertEqual(RUNNER.main(), 1)
        self.assertEqual(verify.call_count, 3)
        streamed.assert_called_once_with(
            ["make", "validate"],
            cwd=repo,
            timeout_seconds=1200,
            phase="validate",
        )
        self.productive_blue_green_mock.assert_called_once()
        reconcile.assert_not_called()

    def test_run_productive_blue_green_propagates_in_memory_receipt_on_persistence_failure(self) -> None:
        self.productive_blue_green.stop()
        receipt = {
            "receipt_sha256": "ab" * 32,
            "outcome": "completed",
            "expected_head": "f" * 40,
            "source_identity_sha256": "cd" * 32,
        }
        error = RUNNER.deploy_dual.ProductionBlueGreenReceiptPersistenceError(
            receipt, OSError("receipt full")
        )
        with patch.object(
            RUNNER.deploy_dual,
            "run_production_blue_green_cutover",
            side_effect=error,
        ):
            result = RUNNER.run_productive_blue_green(
                repo=Path("/tmp/repository"),
                expected_head="f" * 40,
                source_identity_sha256="cd" * 32,
            )
        self.assertEqual(result["outcome"], "completed")
        self.assertFalse(result["receipt_persisted"])
        self.assertIsNone(result["receipt_path"])
        self.assertFalse(result["summary"]["blind_retry_allowed"])

    def test_finalization_binding_and_atomic_receipt_are_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            expected = "a" * 40
            argv_sha256 = "b" * 64
            env = {
                "GRABOWSKI_JOB_ID": "deadbeefcafe",
                "GRABOWSKI_JOB_UNIT": "grabowski-job-deadbeefcafe",
                "GRABOWSKI_JOB_ARGV_SHA256": argv_sha256,
                "GRABOWSKI_JOB_EXPECTED_HEAD": expected,
                "GRABOWSKI_JOB_METADATA_PATH": str(directory / "metadata.json"),
                "GRABOWSKI_JOB_STDOUT_PATH": str(directory / "stdout.log"),
                "GRABOWSKI_JOB_STDERR_PATH": str(directory / "stderr.log"),
                "GRABOWSKI_JOB_FINALIZATION_PATH": str(directory / "finalization.json"),
            }
            with patch.dict(os.environ, env, clear=False):
                binding = RUNNER.load_finalization_binding()
            self.assertIsNotNone(binding)
            with patch.object(RUNNER.time, "time", return_value=1001):
                receipt_path = RUNNER.write_finalization_receipt(
                    binding,
                    final_status="completed",
                    repo_head=expected,
                    release_id="release-test",
                    failure_type=None,
                )
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
            material = {key: value for key, value in payload.items() if key != "payload_sha256"}
            self.assertEqual(payload["payload_sha256"], RUNNER.canonical_json_sha256(material))
            self.assertEqual(payload["job_id"], "deadbeefcafe")
            self.assertEqual(payload["argv_sha256"], argv_sha256)
            self.assertEqual(payload["expected_head"], expected)
            self.assertEqual(payload["final_status"], "completed")
            with self.assertRaises(FileExistsError):
                RUNNER.write_finalization_receipt(
                    binding,
                    final_status="failed",
                    repo_head=None,
                    release_id=None,
                    failure_type="RuntimeError",
                )

    def test_receipt_publish_failure_removes_visible_partial_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            binding = {
                "schema_version": 1,
                "kind": RUNNER.FINALIZATION_KIND,
                "job_id": "deadbeefcafe",
                "unit": "grabowski-job-deadbeefcafe",
                "argv_sha256": "b" * 64,
                "expected_head": "a" * 40,
                "receipt_paths": {
                    "metadata": str(directory / "metadata.json"),
                    "stdout": str(directory / "stdout.log"),
                    "stderr": str(directory / "stderr.log"),
                    "finalization": str(directory / "finalization.json"),
                },
            }
            with patch.object(
                RUNNER.os,
                "fsync",
                side_effect=[None, OSError("directory fsync failed"), None],
            ):
                with self.assertRaisesRegex(OSError, "directory fsync failed"):
                    RUNNER.write_finalization_receipt(
                        binding,
                        final_status="completed",
                        repo_head="a" * 40,
                        release_id="release-test",
                        failure_type=None,
                    )
            self.assertFalse((directory / "finalization.json").exists())
            self.assertEqual(list(directory.glob(".finalization.json.*.tmp")), [])

    def test_verify_live_manifest_rejects_missing_release_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            manifest = home / ".local/share/grabowski-mcp/deployment-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps(
                    {
                        "repo_head": "a" * 40,
                        "completion_status": "complete",
                        "release_id": None,
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(RUNNER.Path, "home", return_value=home):
                with self.assertRaisesRegex(RuntimeError, "release_id is invalid"):
                    RUNNER.verify_live_manifest("a" * 40)

    def test_main_writes_completed_receipt_after_live_manifest_verification(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        binding = {"expected_head": expected}
        with patch.object(sys, "argv", ["runner", "--repo", str(repo), "--canonical-repo", str(repo), "--source-kind", "canonical-main", "--source-identity-sha256", "0" * 64, "--expected-head", expected, "--delay-seconds", "5"]), patch.object(RUNNER, "load_finalization_binding", return_value=binding), patch.object(RUNNER.time, "sleep"), patch.object(RUNNER, "verify_repository"), patch.object(RUNNER, "deployment_contention_preflight", return_value=_contention_result()), patch.object(RUNNER, "run_streamed"), patch.object(RUNNER, "verify_live_manifest", return_value={"release_id": "release", "repo_head": expected, "completion_status": "complete"}), patch.object(RUNNER, "reconcile_coding_agent_sidecars", return_value=_sidecar_reconciliation(expected)), patch.object(RUNNER, "write_finalization_receipt") as write:
            self.assertEqual(RUNNER.main(), 0)
        write.assert_called_once_with(
            binding,
            final_status="completed",
            repo_head=expected,
            release_id="release",
            failure_type=None,
            blue_green=_productive_blue_green_result()["summary"],
        )

    def test_main_preserves_applied_runtime_when_primary_receipt_persistence_fails(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        binding = {"expected_head": expected}
        blue_green = _unpersisted_productive_blue_green_result(expected)
        with patch.object(
            sys, "argv", self._runner_argv(repo, expected)
        ), patch.object(
            RUNNER, "load_finalization_binding", return_value=binding
        ), patch.object(RUNNER.time, "sleep"), patch.object(
            RUNNER, "verify_repository"
        ), patch.object(
            RUNNER,
            "deployment_contention_preflight",
            return_value=_contention_result(),
        ), patch.object(RUNNER, "run_streamed"), patch.object(
            RUNNER, "run_productive_blue_green", return_value=blue_green
        ), patch.object(
            RUNNER,
            "verify_live_manifest",
            return_value={
                "release_id": "release",
                "repo_head": expected,
                "completion_status": "complete",
            },
        ), patch.object(
            RUNNER,
            "reconcile_coding_agent_sidecars",
            return_value=_sidecar_reconciliation(expected),
        ), patch.object(
            RUNNER, "write_finalization_receipt"
        ) as write:
            self.assertEqual(RUNNER.main(), 1)
        write.assert_called_once_with(
            binding,
            final_status="outcome_unknown",
            repo_head=expected,
            release_id="release",
            failure_type="ProductionBlueGreenReceiptPersistenceError",
            blue_green=blue_green["summary"],
        )

    def test_main_preserves_unknown_runtime_when_primary_receipt_persistence_fails(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        binding = {"expected_head": expected}
        blue_green = _unpersisted_outcome_unknown_blue_green_result(expected)
        with patch.object(
            sys, "argv", self._runner_argv(repo, expected)
        ), patch.object(
            RUNNER, "load_finalization_binding", return_value=binding
        ), patch.object(RUNNER.time, "sleep"), patch.object(
            RUNNER, "verify_repository"
        ), patch.object(
            RUNNER,
            "deployment_contention_preflight",
            return_value=_contention_result(),
        ), patch.object(RUNNER, "run_streamed"), patch.object(
            RUNNER, "run_productive_blue_green", return_value=blue_green
        ), patch.object(
            RUNNER, "verify_live_manifest"
        ) as verify_live, patch.object(
            RUNNER, "reconcile_coding_agent_sidecars"
        ) as reconcile, patch.object(
            RUNNER, "write_finalization_receipt"
        ) as write:
            self.assertEqual(RUNNER.main(), 1)
        verify_live.assert_not_called()
        reconcile.assert_not_called()
        write.assert_called_once_with(
            binding,
            final_status="outcome_unknown",
            repo_head=None,
            release_id=None,
            failure_type="BlueGreenDeploymentIncomplete",
            blue_green=blue_green["summary"],
        )

    def test_main_marks_runtime_live_sidecar_failure_as_outstanding(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        binding = {"expected_head": expected}
        with patch.object(
            sys, "argv", self._runner_argv(repo, expected)
        ), patch.object(
            RUNNER, "load_finalization_binding", return_value=binding
        ), patch.object(RUNNER.time, "sleep"), patch.object(
            RUNNER, "verify_repository"
        ), patch.object(
            RUNNER,
            "deployment_contention_preflight",
            return_value=_contention_result(),
        ), patch.object(RUNNER, "run_streamed"), patch.object(
            RUNNER,
            "verify_live_manifest",
            return_value={
                "release_id": "release",
                "repo_head": expected,
                "completion_status": "complete",
            },
        ) as manifest, patch.object(
            RUNNER,
            "reconcile_coding_agent_sidecars",
            side_effect=RuntimeError("sidecar mismatch"),
        ), patch.object(
            RUNNER, "write_finalization_receipt"
        ) as write:
            self.assertEqual(RUNNER.main(), 1)
        manifest.assert_called_once_with(expected)
        write.assert_called_once_with(
            binding,
            final_status="failed",
            repo_head=None,
            release_id=None,
            failure_type="SidecarInstallOutstanding",
            blue_green=_productive_blue_green_result()["summary"],
        )

    def test_main_writes_failed_receipt_for_runner_failure(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        binding = {"expected_head": expected}
        with patch.object(sys, "argv", ["runner", "--repo", str(repo), "--canonical-repo", str(repo), "--source-kind", "canonical-main", "--source-identity-sha256", "0" * 64, "--expected-head", expected, "--delay-seconds", "5"]), patch.object(RUNNER, "load_finalization_binding", return_value=binding), patch.object(RUNNER.time, "sleep"), patch.object(RUNNER, "verify_repository", side_effect=RuntimeError("preflight failed")), patch.object(RUNNER, "write_finalization_receipt") as write:
            self.assertEqual(RUNNER.main(), 1)
        write.assert_called_once_with(
            binding,
            final_status="failed",
            repo_head=None,
            release_id=None,
            failure_type="RuntimeError",
            blue_green=None,
        )

    def test_make_deploy_schedules_not_direct_apply(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            "deploy-apply: context-check chronik-runtime-contract deploy-tooling",
            makefile,
        )
        self.assertIn("tools/deploy_runtime_dual.py --apply", makefile)
        self.assertIn('test "$(BOOTSTRAP_RECOVERY)" = "1"', makefile)
        runner_source = (ROOT / "tools/run_scheduled_deploy.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("run_productive_blue_green", runner_source)
        self.assertNotIn('["make", "deploy-apply"]', runner_source)
        self.assertIn(
            'GRABOWSKI_RUNTIME_PYTHON ?= $(HOME)/.local/share/grabowski-mcp/.venv/bin/python',
            makefile,
        )
        self.assertIn('--source-repository "$(CURDIR)"', makefile)
        self.assertIn('GRABOWSKI_DEPLOY_SOURCE_LEASE_OWNER_ID', makefile)
        self.assertIn('tools/schedule_runtime_deploy.py "$$@"', makefile)
        self.assertIn(
            'runtime-retention-apply: context-check\n>test -x "$(GRABOWSKI_RUNTIME_PYTHON)"',
            makefile,
        )



class RuntimeDeploySchedulerTests(unittest.TestCase):
    def test_schedule_delegates_to_shared_scheduler(self) -> None:
        head = "a" * 40
        repo = "/home/alex/repos/grabowski"
        identity = _source_identity(Path(repo), head)
        receipt = {
            "scheduled": True,
            "already_scheduled": False,
            "expected_head": head,
            "source_identity": identity,
            "source_identity_sha256": identity["identity_sha256"],
            "unit": "grabowski-job-abcdef012345",
        }
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            result = SCHEDULER.schedule(head, 9, repo, None)
        shared.assert_called_once_with(head, 9, repo, None)
        self.assertEqual(result, receipt)

    def test_schedule_binds_requested_source_lease_owner(self) -> None:
        head = "a" * 40
        repo = Path("/home/alex/repos/.grabowski-worktrees/deploy")
        canonical = Path("/home/alex/repos/grabowski")
        identity = _source_identity(
            repo,
            head,
            kind="detached-worktree",
            canonical=canonical,
        )
        material = {
            key: value for key, value in identity.items() if key != "identity_sha256"
        }
        resource_key = f"path:{repo}"
        material["lease_evidence"] = {
            "resource_key": resource_key,
            "lease": {
                "resource_key": resource_key,
                "owner_id": "task:deploy-owner",
                "acquired_at_unix": 10,
                "updated_at_unix": 11,
                "expires_at_unix": 100,
                "metadata_sha256": "b" * 64,
            },
        }
        identity = {
            **material,
            "identity_sha256": SELF_DEPLOY._source_identity_sha256(material),
        }
        receipt = {
            "scheduled": True,
            "expected_head": head,
            "source_identity": identity,
            "source_identity_sha256": identity["identity_sha256"],
        }
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            result = SCHEDULER.schedule(
                head,
                8,
                str(repo),
                "task:deploy-owner",
            )
        self.assertEqual(result, receipt)

        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            with self.assertRaisesRegex(RuntimeError, "different source lease owner"):
                SCHEDULER.schedule(
                    head,
                    8,
                    str(repo),
                    "task:other-owner",
                )

    def test_schedule_rejects_semantically_inconsistent_source_identity(self) -> None:
        head = "a" * 40
        repo = Path("/home/alex/repos/grabowski")
        identity = _source_identity(repo, head)
        material = {
            key: value for key, value in identity.items() if key != "identity_sha256"
        }
        material["source_kind"] = "detached-worktree"
        identity = {
            **material,
            "identity_sha256": SELF_DEPLOY._source_identity_sha256(material),
        }
        receipt = {
            "scheduled": True,
            "expected_head": head,
            "source_identity": identity,
            "source_identity_sha256": identity["identity_sha256"],
        }
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            with self.assertRaisesRegex(RuntimeError, "inconsistent source kind"):
                SCHEDULER.schedule(head, 8, str(repo), None)

    def test_schedule_rejects_unbound_shared_receipt(self) -> None:
        head = "b" * 40
        shared = Mock(return_value={"scheduled": True, "expected_head": "c" * 40})
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            with self.assertRaisesRegex(RuntimeError, "unbound receipt"):
                SCHEDULER.schedule(head, 8)

    def test_schedule_rejects_tampered_source_identity(self) -> None:
        head = "a" * 40
        repo = Path("/home/alex/repos/grabowski")
        identity = _source_identity(repo, head)
        identity["repository"] = "/tmp/tampered"
        receipt = {
            "scheduled": True,
            "expected_head": head,
            "source_identity": identity,
            "source_identity_sha256": identity["identity_sha256"],
        }
        shared = Mock(return_value=receipt)
        with patch.object(SCHEDULER, "_load_runtime_scheduler", return_value=shared):
            with self.assertRaisesRegex(RuntimeError, "unbound receipt"):
                SCHEDULER.schedule(head, 8)

    def test_schedule_bounds_head_and_delay_seconds(self) -> None:
        with self.assertRaises(ValueError):
            SCHEDULER.schedule("not-a-head", 8)
        with self.assertRaises(ValueError):
            SCHEDULER.schedule("d" * 40, 4)
        with self.assertRaises(ValueError):
            SCHEDULER.schedule("d" * 40, 61)
        with self.assertRaisesRegex(ValueError, "bounded absolute path"):
            SCHEDULER.schedule("d" * 40, 8, "relative/repo")
        with self.assertRaisesRegex(ValueError, "source_lease_owner_id"):
            SCHEDULER.schedule("d" * 40, 8, "/tmp/repo", "owner with spaces")



if __name__ == "__main__":
    unittest.main()


class IndexedInflightJobEvidenceTests(unittest.TestCase):
    """The deploy index -- not just its reservation -- decides "already running".

    ``pending_unit`` is cleared the moment a job starts, so a gate that read only
    that field saw an empty index for the entire life of a running job. Two
    identical repairs could therefore both dispatch: the double dispatch this
    covers.
    """

    DEPLOY_ARGV = [
        "/usr/bin/python3",
        "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
        "--repo",
        "/home/alex/repos/grabowski",
        "--canonical-repo",
        "/home/alex/repos/grabowski",
        "--source-kind",
        "canonical-main",
        "--source-identity-sha256",
        "ab" * 32,
        "--expected-head",
        "a" * 40,
        "--delay-seconds",
        "8",
    ]

    def _projection(self, *, units, pending, classify, command=None, prune=False):
        self_deploy = SELF_DEPLOY
        with (
            mock.patch.object(
                self_deploy.operator, "_jobs_root", return_value=Path("/jobs")
            ),
            mock.patch.object(
                self_deploy,
                "_deploy_index",
                return_value={"units": list(units), "pending_unit": pending},
            ),
            mock.patch.object(self_deploy, "_write_deploy_index") as write,
            mock.patch.object(self_deploy, "_classify_indexed_job", side_effect=classify),
        ):
            evidence = self_deploy.inflight_runtime_job_evidence(command, prune=prune)
        return evidence, write

    @staticmethod
    def _entry(unit, *, kind="deploy", argv_sha256="cd" * 32, final_status="running"):
        return {
            "unit": unit,
            "kind": kind,
            "argv": [],
            "argv_sha256": argv_sha256,
            "metadata": {},
            "status": {},
            "final_status": final_status,
            "fields": {},
            "terminal": final_status in {"completed", "succeeded", "failed", "launch_failed"},
            "reusable": final_status == "running",
        }

    def test_pending_reservation_still_blocks(self) -> None:
        evidence, _ = self._projection(
            units=[], pending="grabowski-job-aaaaaaaaaaaa", classify=lambda entry: None
        )
        self.assertIn("grabowski-job-aaaaaaaaaaaa", evidence["blocking_units"])

    def test_started_job_blocks_after_the_reservation_is_cleared(self) -> None:
        """The exact window the old check was blind to."""
        evidence, _ = self._projection(
            units=["grabowski-job-bbbbbbbbbbbb"],
            pending=None,
            classify=lambda entry: self._entry(entry.name),
        )
        self.assertEqual(evidence["blocking_units"], ["grabowski-job-bbbbbbbbbbbb"])
        self.assertIsNone(evidence["idempotent_match"])

    def test_identical_running_repair_is_coalesced_not_blocked(self) -> None:
        expected = SELF_DEPLOY._deploy_command_sha256(self.DEPLOY_ARGV)
        evidence, _ = self._projection(
            units=["grabowski-job-cccccccccccc"],
            pending=None,
            classify=lambda entry: self._entry(entry.name, argv_sha256=expected),
            command=self.DEPLOY_ARGV,
        )
        self.assertEqual(evidence["blocking_units"], [])
        self.assertEqual(
            evidence["idempotent_match"]["unit"], "grabowski-job-cccccccccccc"
        )

    def test_foreign_head_deploy_blocks_fail_closed(self) -> None:
        evidence, _ = self._projection(
            units=["grabowski-job-dddddddddddd"],
            pending=None,
            classify=lambda entry: self._entry(entry.name, argv_sha256="ef" * 32),
            command=self.DEPLOY_ARGV,
        )
        self.assertEqual(evidence["blocking_units"], ["grabowski-job-dddddddddddd"])
        self.assertIsNone(evidence["idempotent_match"])

    def test_non_reusable_outcome_is_never_coalesced(self) -> None:
        expected = SELF_DEPLOY._deploy_command_sha256(self.DEPLOY_ARGV)
        evidence, _ = self._projection(
            units=["grabowski-job-eeeeeeeeeeee"],
            pending=None,
            classify=lambda entry: self._entry(
                entry.name, argv_sha256=expected, final_status="outcome_unknown"
            ),
            command=self.DEPLOY_ARGV,
        )
        # An ambiguous job is not "ours to reuse"; it is a reason to stop.
        self.assertIsNone(evidence["idempotent_match"])
        self.assertEqual(evidence["blocking_units"], ["grabowski-job-eeeeeeeeeeee"])

    def test_mid_cutover_resume_coexists_and_blocks_a_deploy(self) -> None:
        evidence, _ = self._projection(
            units=["grabowski-job-ffffffffffff"],
            pending=None,
            classify=lambda entry: self._entry(entry.name, kind="midcutover_resume"),
            command=self.DEPLOY_ARGV,
        )
        self.assertEqual(evidence["blocking_units"], ["grabowski-job-ffffffffffff"])

    def test_terminal_entries_are_pruned_and_do_not_block(self) -> None:
        evidence, write = self._projection(
            units=["grabowski-job-111111111111", "grabowski-job-222222222222"],
            pending=None,
            classify=lambda entry: self._entry(
                entry.name,
                final_status=(
                    "completed" if entry.name.endswith("111111111111") else "running"
                ),
            ),
            prune=True,
        )
        self.assertEqual(evidence["pruned_units"], ["grabowski-job-111111111111"])
        self.assertEqual(evidence["blocking_units"], ["grabowski-job-222222222222"])
        write.assert_called_once()
        self.assertEqual(
            write.call_args.kwargs["units"], ["grabowski-job-222222222222"]
        )

    def test_unreadable_entry_blocks_rather_than_disappears(self) -> None:
        def explode(entry):
            raise SELF_DEPLOY.IndexedRuntimeJobConflict("unreadable")

        evidence, write = self._projection(
            units=["grabowski-job-333333333333"],
            pending=None,
            classify=explode,
            prune=True,
        )
        self.assertEqual(evidence["blocking_units"], ["grabowski-job-333333333333"])
        self.assertIsNotNone(evidence["error"])
        write.assert_not_called()


class BootstrapIndexRunnerRecognitionTests(unittest.TestCase):
    """A rebuilt index must retain every live runner that touches the runtime.

    The bootstrap runs when the index file is missing. Recognising only the
    deploy runner there dropped a live mid-cutover resume before any later
    reader could see it, so an ordinary deployment could be scheduled straight
    into the recovery it was meant to wait for.
    """

    def _bootstrap(self, jobs, *, final_status="running"):
        entries = [Path(f"/jobs/{unit}") for unit in jobs]

        def metadata(unit):
            return {"argv": jobs[unit], "final_status": final_status}

        root = mock.Mock()
        root.iterdir.return_value = entries
        written = {}

        def write(_root, *, units, pending_unit):
            written["units"] = list(units)
            written["pending_unit"] = pending_unit
            return {"units": list(units), "pending_unit": pending_unit}

        with (
            mock.patch.object(SELF_DEPLOY, "_durable_job_unit", return_value=True),
            mock.patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", side_effect=metadata
            ),
            mock.patch.object(SELF_DEPLOY, "_write_deploy_index", side_effect=write),
            mock.patch.object(
                SELF_DEPLOY, "_deploy_finalization_retry_block", return_value=False
            ),
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_dir", return_value=True),
        ):
            SELF_DEPLOY._bootstrap_deploy_index(root)
        return written

    @staticmethod
    def _argv(runner):
        return ["/usr/bin/python3", f"/home/alex/repos/grabowski/{runner}", "--repo", "/x"]

    def test_live_resume_job_is_retained(self) -> None:
        written = self._bootstrap(
            {
                "grabowski-job-aaaaaaaaaaaa": self._argv(
                    SELF_DEPLOY.MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH
                )
            }
        )
        self.assertEqual(written["units"], ["grabowski-job-aaaaaaaaaaaa"])

    def test_live_deploy_job_is_still_retained(self) -> None:
        written = self._bootstrap(
            {
                "grabowski-job-bbbbbbbbbbbb": self._argv(
                    SELF_DEPLOY.RUNNER_RELATIVE_PATH
                )
            }
        )
        self.assertEqual(written["units"], ["grabowski-job-bbbbbbbbbbbb"])

    def test_terminal_resume_job_is_not_retained(self) -> None:
        written = self._bootstrap(
            {
                "grabowski-job-cccccccccccc": self._argv(
                    SELF_DEPLOY.MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH
                )
            },
            final_status="completed",
        )
        self.assertEqual(written["units"], [])

    def test_unrelated_job_is_ignored(self) -> None:
        written = self._bootstrap(
            {"grabowski-job-dddddddddddd": ["/usr/bin/python3", "/tmp/other.py"]}
        )
        self.assertEqual(written["units"], [])


class ReadbackRequiredAndAmbiguityTests(unittest.TestCase):
    """Two ways a job can look finished without being safe to move past."""

    ARGV = [
        "/usr/bin/python3",
        "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
        "--repo",
        "/home/alex/repos/grabowski",
        "--canonical-repo",
        "/home/alex/repos/grabowski",
        "--source-kind",
        "canonical-main",
        "--source-identity-sha256",
        "ab" * 32,
        "--expected-head",
        "a" * 40,
        "--delay-seconds",
        "8",
    ]

    def _classified(self, unit, *, status):
        """Run the real classifier against a realistic job status shape."""
        metadata = {
            "argv": list(self.ARGV),
            "argv_sha256": SELF_DEPLOY._deploy_command_sha256(self.ARGV),
            "cwd": "/home/alex/repos/grabowski",
        }
        with (
            mock.patch.object(
                SELF_DEPLOY.operator, "_read_job_metadata", return_value=metadata
            ),
            mock.patch.object(
                SELF_DEPLOY.operator, "grabowski_job_status", return_value=status
            ),
            mock.patch.object(Path, "is_symlink", return_value=False),
            mock.patch.object(Path, "is_dir", return_value=True),
        ):
            return SELF_DEPLOY._classify_indexed_job(Path(f"/jobs/{unit}"))

    def test_terminal_unit_with_readback_required_receipt_is_not_terminal(self) -> None:
        """The real shape: the unit exited cleanly, the receipt says otherwise."""
        classified = self._classified(
            "grabowski-job-aaaaaaaaaaaa",
            status={
                "final_status": "succeeded",
                "finalization_receipt": {
                    "valid": True,
                    "final_status": "outcome_unknown",
                    "blind_retry_allowed": False,
                },
            },
        )
        self.assertTrue(classified["readback_required"])
        # Pruning this entry would drop the one job that demands a readback.
        self.assertFalse(classified["terminal"])
        self.assertFalse(classified["reusable"])

    def test_terminal_unit_with_settled_receipt_is_terminal(self) -> None:
        classified = self._classified(
            "grabowski-job-bbbbbbbbbbbb",
            status={
                "final_status": "succeeded",
                "finalization_receipt": {
                    "valid": True,
                    "final_status": "completed",
                    "blind_retry_allowed": None,
                },
            },
        )
        self.assertFalse(classified["readback_required"])
        self.assertTrue(classified["terminal"])

    def test_readback_required_entry_blocks_and_is_not_pruned(self) -> None:
        def classify(entry):
            return {
                "unit": entry.name,
                "kind": "deploy",
                "argv": [],
                "argv_sha256": SELF_DEPLOY._deploy_command_sha256(self.ARGV),
                "metadata": {},
                "status": {},
                "final_status": "succeeded",
                "fields": {},
                "readback_required": True,
                "terminal": False,
                "reusable": False,
            }

        with (
            mock.patch.object(
                SELF_DEPLOY.operator, "_jobs_root", return_value=Path("/jobs")
            ),
            mock.patch.object(
                SELF_DEPLOY,
                "_deploy_index",
                return_value={
                    "units": ["grabowski-job-cccccccccccc"],
                    "pending_unit": None,
                },
            ),
            mock.patch.object(SELF_DEPLOY, "_write_deploy_index") as write,
            mock.patch.object(SELF_DEPLOY, "_classify_indexed_job", side_effect=classify),
        ):
            evidence = SELF_DEPLOY.inflight_runtime_job_evidence(self.ARGV, prune=True)
        self.assertEqual(evidence["pruned_units"], [])
        self.assertEqual(evidence["blocking_units"], ["grabowski-job-cccccccccccc"])
        self.assertIsNone(evidence["idempotent_match"])
        write.assert_not_called()

    def test_two_identical_running_jobs_are_ambiguous_not_coalesced(self) -> None:
        """Historical double-dispatch residue must not be silently joined."""
        expected = SELF_DEPLOY._deploy_command_sha256(self.ARGV)

        def classify(entry):
            return {
                "unit": entry.name,
                "kind": "deploy",
                "argv": [],
                "argv_sha256": expected,
                "metadata": {},
                "status": {},
                "final_status": "running",
                "fields": {},
                "readback_required": False,
                "terminal": False,
                "reusable": True,
            }

        with (
            mock.patch.object(
                SELF_DEPLOY.operator, "_jobs_root", return_value=Path("/jobs")
            ),
            mock.patch.object(
                SELF_DEPLOY,
                "_deploy_index",
                return_value={
                    "units": [
                        "grabowski-job-dddddddddddd",
                        "grabowski-job-eeeeeeeeeeee",
                    ],
                    "pending_unit": None,
                },
            ),
            mock.patch.object(SELF_DEPLOY, "_write_deploy_index"),
            mock.patch.object(SELF_DEPLOY, "_classify_indexed_job", side_effect=classify),
        ):
            evidence = SELF_DEPLOY.inflight_runtime_job_evidence(self.ARGV)
        self.assertIsNone(evidence["idempotent_match"])
        self.assertEqual(
            evidence["ambiguous_identical_units"],
            ["grabowski-job-dddddddddddd", "grabowski-job-eeeeeeeeeeee"],
        )
        self.assertEqual(
            sorted(set(evidence["blocking_units"])),
            ["grabowski-job-dddddddddddd", "grabowski-job-eeeeeeeeeeee"],
        )
        self.assertIn("multiple identical runtime jobs", evidence["error"])
