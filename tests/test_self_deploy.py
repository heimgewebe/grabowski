from __future__ import annotations

from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
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
    name = "grabowski_self_deploy_test"
    spec = importlib.util.spec_from_file_location(name, ROOT / "src" / "grabowski_self_deploy.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load self deploy module")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"mcp": fake_mcp, "mcp.types": fake_types, "pydantic": fake_pydantic, "grabowski_operator_core": operator, "grabowski_mcp": base, "grabowski_read_surface": read_surface, name: module}, clear=False):
        spec.loader.exec_module(module)
    return module

def _result(stdout: str = "", returncode: int = 0) -> dict[str, object]:
    return {"returncode": returncode, "timed_out": False, "stdout_truncated": False, "stderr_truncated": False, "stdout": stdout, "stderr": ""}

SELF_DEPLOY = _load_self_deploy()

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
        with patch.object(SELF_DEPLOY, "_resource_inspect", return_value=payload):
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

    def test_main_validates_before_deploying(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        with patch.object(sys, "argv", ["runner", "--repo", str(repo), "--canonical-repo", str(repo), "--source-kind", "canonical-main", "--source-identity-sha256", "0" * 64, "--expected-head", expected, "--delay-seconds", "5"]), patch.object(RUNNER, "load_finalization_binding", return_value=None), patch.object(RUNNER.time, "sleep"), patch.object(RUNNER, "verify_repository") as verify, patch.object(RUNNER, "run_streamed") as streamed, patch.object(RUNNER, "verify_live_manifest", return_value={"release_id": "r", "repo_head": expected, "completion_status": "complete"}):
            self.assertEqual(RUNNER.main(), 0)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(streamed.call_args_list[0].args[0], ["make", "validate"])
        self.assertEqual(streamed.call_args_list[1].args[0], ["make", "deploy-apply"])

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
        with patch.object(sys, "argv", ["runner", "--repo", str(repo), "--canonical-repo", str(repo), "--source-kind", "canonical-main", "--source-identity-sha256", "0" * 64, "--expected-head", expected, "--delay-seconds", "5"]), patch.object(RUNNER, "load_finalization_binding", return_value=binding), patch.object(RUNNER.time, "sleep"), patch.object(RUNNER, "verify_repository"), patch.object(RUNNER, "run_streamed"), patch.object(RUNNER, "verify_live_manifest", return_value={"release_id": "release", "repo_head": expected, "completion_status": "complete"}), patch.object(RUNNER, "write_finalization_receipt") as write:
            self.assertEqual(RUNNER.main(), 0)
        write.assert_called_once_with(
            binding,
            final_status="completed",
            repo_head=expected,
            release_id="release",
            failure_type=None,
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
        )

    def test_make_deploy_schedules_not_direct_apply(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("deploy-apply: context-check deploy-tooling", makefile)
        self.assertIn("tools/deploy_runtime_dual.py --apply", makefile)
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

    def test_schedule_rejects_unbound_shared_receipt(self) -> None:
        head = "b" * 40
        shared = Mock(return_value={"scheduled": True, "expected_head": "c" * 40})
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
