"""The provenance repair lane must open only on independent evidence.

Every check here guards the same invariant: a fail-closed integrity gate may
not close over its own repair path, but the escape hatch it needs must not
become a way around the gate for anything else.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

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


class _FakeField:
    def __init__(self, *args, **kwargs):
        pass


def _load_provenance_recovery():
    """Load the lane against stubs; its dependencies are patched per test."""
    import importlib.util
    import os

    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_fastmcp.Context = object
    fake_types.ToolAnnotations = _FakeToolAnnotations
    fake_pydantic = types.ModuleType("pydantic")
    fake_pydantic.Field = lambda **kwargs: kwargs

    operator = types.ModuleType("grabowski_operator_core")
    operator.mcp = _FakeFastMCP()
    operator._safe_environment = lambda: dict(os.environ)
    operator._jobs_root = lambda: Path("/nonexistent-jobs-root")
    operator._start_job = lambda *args, **kwargs: {}
    operator._require_operator_capability = lambda capability: None
    operator._argv_hash = lambda argv: "a" * 64
    class _JobDispatchUnknown(RuntimeError):
        def __init__(self, message, *, unit, evidence):
            super().__init__(message)
            self.unit = unit
            self.evidence = evidence
    operator.JobDispatchUnknown = _JobDispatchUnknown
    base = types.ModuleType("grabowski_mcp")
    base.AUDIT_LOG = Path("/nonexistent-audit.jsonl")
    base._deployment_metadata = lambda: {}
    base._verify_audit_log = lambda path=None: {}
    base._kill_switch_state = lambda: {}
    base._append_audit = lambda record: None
    base._append_audit_with_digest = lambda record: "0" * 64
    base._require_valid_audit_chain = lambda: None
    base._require_blockade_allows_mutation = lambda *args, **kwargs: None
    privileged = types.ModuleType("grabowski_privileged")
    privileged.grabowski_privileged_broker_status = lambda: {}
    recovery = types.ModuleType("grabowski_recovery")
    recovery.BACKUP_SUCCESS = Path("/nonexistent-backup-marker")
    recovery._fresh_text_marker = lambda path: {}
    sys.modules.setdefault("grabowski_runtime_contract", __import__("grabowski_runtime_contract"))
    self_deploy = types.ModuleType("grabowski_self_deploy")
    self_deploy.ExpectedHead = str
    self_deploy.SourceRepository = str
    self_deploy.SourceLeaseOwner = str
    self_deploy.RUNNER_RELATIVE_PATH = Path("tools/run_scheduled_deploy.py")
    self_deploy.MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH = Path(
        "tools/run_midcutover_resume.py"
    )
    self_deploy.CANONICAL_REPOSITORY = Path("/nonexistent-repo")
    self_deploy.DEPLOY_JOB_PREFIX = "grabowski-job-"
    self_deploy._deployment_source_preflight = lambda *args, **kwargs: None
    self_deploy._deploy_command = lambda *args, **kwargs: ["python3"]
    self_deploy._midcutover_resume_command = lambda *args, **kwargs: ["python3"]
    self_deploy._deploy_index = lambda root: {"units": [], "pending_unit": None}
    self_deploy._write_deploy_index = lambda *args, **kwargs: None
    self_deploy._deploy_schedule_lock = contextlib.nullcontext

    name = "grabowski_provenance_recovery_test"
    spec = importlib.util.spec_from_file_location(
        name, SRC / "grabowski_provenance_recovery.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load grabowski_provenance_recovery")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        sys.modules,
        {
            "mcp": fake_mcp,
            "mcp.server": fake_server,
            "mcp.server.fastmcp": fake_fastmcp,
            "mcp.types": fake_types,
            "pydantic": fake_pydantic,
            "grabowski_operator_core": operator,
            "grabowski_mcp": base,
            "grabowski_privileged": privileged,
            "grabowski_recovery": recovery,
            "grabowski_self_deploy": self_deploy,
            name: module,
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module


provenance_recovery = _load_provenance_recovery()

HEAD = "a" * 40
OTHER_HEAD = "b" * 40


def _source_identity(repository: Path) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "grabowski_runtime_deploy_source_identity",
        "source_kind": "canonical-main",
        "repository": str(repository),
        "canonical_repository": str(repository),
        "git_common_directory": str(repository / ".git"),
        "head": HEAD,
        "origin_main": HEAD,
        "clean": True,
        "lease_evidence": {},
        "identity_sha256": "c" * 64,
    }


class ProvenanceRecoveryGateTests(unittest.TestCase):
    """evaluate_gate must demand every independent precondition."""

    def setUp(self) -> None:
        self.repository = Path("/home/alex/repos/grabowski")

    def _gate(
        self,
        *,
        deployment: dict | None = None,
        audit: dict | None = None,
        kill_switch: dict | None = None,
        backup: dict | None = None,
        broker: dict | None = None,
        source_raises: Exception | None = None,
        target: dict | None = None,
        competing: dict | None = None,
        blockade: dict | None = None,
    ) -> dict:
        deployment = deployment or {
            # The observed deadlock: built complete, judged invalid.
            "completion_status": "complete",
            "release_id": "release-broken",
            "repo_head": OTHER_HEAD,
            "manifest_schema_valid": False,
            "entrypoint_contract_identity_valid": False,
            "artifact_integrity_valid": False,
            "provenance_valid": False,
        }
        audit = audit or {"valid": True, "audit_writable": True, "records": 10}
        kill_switch = kill_switch or {"engaged": False}
        backup = backup or {"valid": True, "age_seconds": 100}
        broker = broker or {"ready": True}
        target = target or {
            "contract_readable": True,
            "validator_readable": True,
            "contract_valid": True,
            "validator_is_deployed": True,
            "error": None,
        }
        competing = competing or {
            "deploy_lock_free": True,
            "inflight_deploy_jobs": [],
            "error": None,
        }
        blockade = blockade or {"allows_mutation": True, "error": None}

        def preflight(*args, **kwargs):
            if source_raises is not None:
                raise source_raises
            return self.repository, self.repository / "runner", _source_identity(
                self.repository
            )

        with (
            patch.object(
                provenance_recovery.base, "_deployment_metadata", return_value=deployment
            ),
            patch.object(
                provenance_recovery.base, "_verify_audit_log", return_value=audit
            ),
            patch.object(
                provenance_recovery.base, "_kill_switch_state", return_value=kill_switch
            ),
            patch.object(
                provenance_recovery.recovery, "_fresh_text_marker", return_value=backup
            ),
            patch.object(
                provenance_recovery.privileged,
                "grabowski_privileged_broker_status",
                return_value=broker,
            ),
            patch.object(
                provenance_recovery.self_deploy,
                "_deployment_source_preflight",
                side_effect=preflight,
            ),
            patch.object(
                provenance_recovery, "_target_contract_evidence", return_value=target
            ),
            patch.object(
                provenance_recovery,
                "_competing_deployment_evidence",
                return_value=competing,
            ),
            patch.object(
                provenance_recovery, "_blockade_evidence", return_value=blockade
            ),
            patch.object(
                provenance_recovery,
                "_recovery_lane",
                return_value={
                    "lane": provenance_recovery.midcutover.LANE_SCHEDULED_DEPLOY,
                    "resume_binding": None,
                    "reasons": [],
                },
            ),
        ):
            return provenance_recovery.evaluate_gate(HEAD)

    def test_full_independent_evidence_opens_the_lane(self) -> None:
        gate = self._gate()

        self.assertTrue(gate["allowed"], gate["reasons"])
        self.assertEqual(gate["reasons"], [])
        self.assertTrue(gate["runtime_integrity"]["repair_warranted"])

    def test_lane_is_closed_when_the_runtime_is_healthy(self) -> None:
        """The lane must never be a way around gates that currently apply."""
        gate = self._gate(
            deployment={
                "completion_status": "complete",
                "release_id": "release-good",
                "repo_head": HEAD,
                "manifest_schema_valid": True,
                "entrypoint_contract_identity_valid": True,
                "artifact_integrity_valid": True,
                "provenance_valid": True,
            }
        )

        self.assertFalse(gate["allowed"])
        self.assertIn("repair_warranted", gate["reasons"])

    def test_each_independent_precondition_closes_the_lane_alone(self) -> None:
        cases = {
            "audit_chain_valid": {"audit": {"valid": False, "audit_writable": False}},
            "audit_writable": {"audit": {"valid": True, "audit_writable": False}},
            "kill_switch_clear": {"kill_switch": {"engaged": True}},
            "local_backup_marker_fresh": {"backup": {"valid": False}},
            "privileged_broker_ready": {"broker": {"ready": False}},
            "source_identity_bound": {
                "source_raises": RuntimeError("source repository is dirty")
            },
            "target_contract_valid": {
                "target": {
                    "contract_valid": False,
                    "validator_is_deployed": False,
                    "error": "target contract is invalid",
                }
            },
            "target_deploys_canonical_validator": {
                "target": {"contract_valid": True, "validator_is_deployed": False}
            },
            "no_competing_deployment": {
                "competing": {
                    "deploy_lock_free": False,
                    "inflight_deploy_jobs": [],
                    "error": None,
                }
            },
            "no_blocking_operator_blockade": {
                "blockade": {
                    "allows_mutation": False,
                    "error": "blockade denies mutation",
                }
            },
        }
        for reason, override in cases.items():
            with self.subTest(reason):
                gate = self._gate(**override)
                self.assertFalse(gate["allowed"])
                self.assertIn(reason, gate["reasons"])

    def test_inflight_deployment_closes_the_lane(self) -> None:
        gate = self._gate(
            competing={
                "deploy_lock_free": True,
                "inflight_deploy_jobs": ["grabowski-deploy-abc"],
                "error": None,
            }
        )

        self.assertFalse(gate["allowed"])
        self.assertIn("no_competing_deployment", gate["reasons"])

    def test_gate_declares_its_authority_limits(self) -> None:
        gate = self._gate()
        authority = gate["authority_model"]

        self.assertFalse(authority["derives_from_runtime_provenance"])
        self.assertFalse(authority["grants_shell_authority"])
        self.assertFalse(authority["grants_power_worker_authority"])
        self.assertEqual(
            authority["effect_scope"],
            "runtime-rebuild-and-activation-of-expected-head",
        )

    def test_denied_repair_raises_and_starts_no_job(self) -> None:
        with (
            patch.object(
                provenance_recovery,
                "evaluate_gate",
                return_value={
                    "allowed": False,
                    "reasons": ["kill_switch_clear"],
                    "runtime_integrity": {"failed_integrity_flags": ["provenance_valid"]},
                },
            ),
            patch.object(provenance_recovery.base, "_append_audit") as audit,
            patch.object(provenance_recovery.operator, "_start_job") as start_job,
        ):
            with self.assertRaises(provenance_recovery.ProvenanceRecoveryDenied) as raised:
                provenance_recovery.grabowski_recovery_provenance_repair(HEAD)

        self.assertEqual(raised.exception.reasons, ["kill_switch_clear"])
        start_job.assert_not_called()
        audit.assert_called_once()
        self.assertEqual(
            audit.call_args[0][0]["operation"], "provenance-recovery-denied"
        )


class VolatileGateRecheckTests(unittest.TestCase):
    """Gates that can flip between assessment and dispatch are re-read."""

    def _repair_with_recheck(self, recheck: dict):
        allowed_gate = {
            "allowed": True,
            "reasons": [],
            "runtime_integrity": {"failed_integrity_flags": ["provenance_valid"]},
            "source_identity": _source_identity(ROOT),
        }
        with (
            patch.object(provenance_recovery, "evaluate_gate", return_value=allowed_gate),
            patch.object(
                provenance_recovery, "_volatile_gate_recheck", return_value=recheck
            ),
            patch.object(provenance_recovery.base, "_append_audit") as audit,
            patch.object(provenance_recovery.operator, "_start_job") as start_job,
        ):
            raised = None
            try:
                provenance_recovery.grabowski_recovery_provenance_repair(HEAD)
            except provenance_recovery.ProvenanceRecoveryDenied as exc:
                raised = exc
        return raised, start_job, audit

    def test_kill_switch_engaged_after_assessment_aborts_dispatch(self) -> None:
        raised, start_job, audit = self._repair_with_recheck(
            {"reasons": ["kill_switch_clear"], "checks": {}}
        )

        self.assertIsNotNone(raised)
        self.assertEqual(raised.reasons, ["kill_switch_clear"])
        start_job.assert_not_called()
        self.assertEqual(
            audit.call_args[0][0]["operation"],
            "provenance-recovery-aborted-before-dispatch",
        )

    def test_competing_deployment_appearing_late_aborts_dispatch(self) -> None:
        raised, start_job, _audit = self._repair_with_recheck(
            {"reasons": ["no_competing_deployment"], "checks": {}}
        )

        self.assertIsNotNone(raised)
        start_job.assert_not_called()


class TargetContractEvidenceTests(unittest.TestCase):
    """The repair target is judged before it is ever built."""

    @staticmethod
    def _verified_anchor():
        """A verified anchor carrying the real schema, for contract-level tests.

        Anchor provenance itself is covered separately in TrustAnchorTests; here
        we want to reach the contract logic behind it.
        """
        data = (SRC / "grabowski_runtime_contract.py").read_bytes()
        return patch.object(
            provenance_recovery,
            "_verified_trust_anchor",
            return_value={
                "verified": True, "reason": None, "present": True,
                "path": "/etc/grabowski/runtime-contract-schema.py",
                "sha256": "0" * 64, "source": data,
            },
        )

    def test_matching_schema_yields_a_decisive_verdict(self) -> None:
        """When the target ships the trusted schema, this process can judge it."""
        trusted = (SRC / "grabowski_runtime_contract.py").read_bytes()
        contract = (ROOT / "config" / "runtime-entrypoint.json").read_bytes()
        with self._verified_anchor(), patch.object(
            provenance_recovery, "_git_bytes"
        ) as git_bytes:
            git_bytes.side_effect = lambda repo, *args: (
                contract if args[-1].endswith(".json") else trusted
            )
            evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertIsNone(evidence["error"])
        self.assertFalse(evidence["indeterminate"])
        self.assertTrue(evidence["validator_matches_trusted_schema"])
        self.assertTrue(evidence["contract_valid"])
        self.assertTrue(evidence["validator_is_deployed"])

    def test_commit_without_canonical_validator_is_refused(self) -> None:
        """Repairing into a runtime that cannot validate itself is refused."""
        with patch.object(provenance_recovery, "_git_bytes") as git_bytes:
            git_bytes.side_effect = lambda repo, *args: (
                b'{"schema_version": 4}' if "config" in args[-1] else None
            )
            evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertFalse(evidence["contract_valid"])
        self.assertIn("canonical contract validator", evidence["error"])

    def test_validator_raising_at_module_scope_fails_closed(self) -> None:
        """A broken target validator must fail the check, not crash the gate.

        The assessment surface is what an operator reaches for when the runtime
        is already broken; if a bad commit could crash it, the repair path goes
        down with the runtime.
        """
        broken = b"raise RuntimeError('validator exploded at import')\n"
        with patch.object(provenance_recovery, "_git_bytes") as git_bytes:
            git_bytes.side_effect = lambda repo, *args: (
                b"{}" if args[-1].endswith(".json") else broken
            )
            evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertFalse(evidence["contract_valid"])
        self.assertTrue(evidence["indeterminate"])
        self.assertFalse(evidence["executed_candidate_code"])

    def test_validator_with_name_error_is_never_evaluated(self) -> None:
        """Broken candidate code is inert now: it is compared, not executed."""
        broken = b"CANONICAL_VALIDATOR_MODULE = undefined_name\n"
        with patch.object(provenance_recovery, "_git_bytes") as git_bytes:
            git_bytes.side_effect = lambda repo, *args: (
                b"{}" if args[-1].endswith(".json") else broken
            )
            evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertFalse(evidence["contract_valid"])
        self.assertTrue(evidence["indeterminate"])
        self.assertFalse(evidence["executed_candidate_code"])

    def test_no_candidate_code_is_executed_at_all(self) -> None:
        """The read path must not run the target revision, in-process or out.

        A subprocess was not enough: same UID, same filesystem, so a candidate
        could still write files or spawn processes merely by being assessed.
        The design now compares the candidate's schema with the trusted one and
        judges with the trusted verifier, so a hostile payload is inert.
        """
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "escape"
            hostile = (
                f"import pathlib; pathlib.Path({str(marker)!r}).write_text('x')\n"
                "CANONICAL_VALIDATOR_MODULE = 'grabowski_runtime_contract'\n"
                "def contract_error(raw):\n    return None\n"
            ).encode()
            with patch.object(provenance_recovery, "_git_bytes") as git_bytes:
                git_bytes.side_effect = lambda repo, *args: (
                    b'{"module": "grabowski_runtime_contract"}'
                    if args[-1].endswith(".json")
                    else hostile
                )
                evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

            self.assertFalse(marker.exists(), "candidate code was executed")
        self.assertFalse(evidence["executed_candidate_code"])
        self.assertTrue(evidence["indeterminate"])
        self.assertFalse(evidence["contract_valid"])

    def test_differing_target_schema_is_indeterminate_not_rejected(self) -> None:
        """A schema change is 'I cannot judge this', not 'this is broken'."""
        with self._verified_anchor(), patch.object(
            provenance_recovery, "_git_bytes"
        ) as git_bytes:
            git_bytes.side_effect = lambda repo, *args: (
                b"{}" if args[-1].endswith(".json") else b"# a different schema\n"
            )
            evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertTrue(evidence["indeterminate"])
        self.assertFalse(evidence["validator_matches_trusted_schema"])
        self.assertIn("different canonical contract schema", evidence["error"])

    def test_canonical_validator_identity_is_not_taken_from_the_candidate(self) -> None:
        """The artifact under review may not define what proves its own schema."""
        source = (SRC / "grabowski_provenance_recovery.py").read_text(encoding="utf-8")

        self.assertIn('CANONICAL_VALIDATOR_MODULE = "grabowski_runtime_contract"', source)
        self.assertIn(
            'CANONICAL_VALIDATOR_SOURCE = "src/grabowski_runtime_contract.py"', source
        )
        self.assertNotIn('namespace["CANONICAL_VALIDATOR_MODULE"]', source)

    def test_contract_mapping_of_the_validator_module_is_pinned(self) -> None:
        """Deploying the schema under a different path must be refused."""
        import copy as _copy

        contract = _copy.deepcopy(
            json.loads((ROOT / "config" / "runtime-entrypoint.json").read_text())
        )
        for item in contract["supporting_sources"]:
            if item["module"] == "grabowski_runtime_contract":
                item["source"] = "src/grabowski_capabilities.py"
        payload = json.dumps(contract).encode()
        trusted = (SRC / "grabowski_runtime_contract.py").read_bytes()
        with patch.object(provenance_recovery, "_git_bytes") as git_bytes:
            git_bytes.side_effect = lambda repo, *args: (
                payload if args[-1].endswith(".json") else trusted
            )
            evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertFalse(evidence["validator_is_deployed"])

    def test_invalid_target_contract_is_refused(self) -> None:
        """A target whose own schema rejects its own contract is not a repair."""
        validator = (SRC / "grabowski_runtime_contract.py").read_bytes()
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        contract["unreviewed_capability"] = True
        payload = json.dumps(contract).encode("utf-8")

        with self._verified_anchor(), patch.object(
            provenance_recovery, "_git_bytes"
        ) as git_bytes:
            git_bytes.side_effect = lambda repo, *args: (
                payload if args[-1].endswith(".json") else validator
            )
            evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertFalse(evidence["contract_valid"])
        self.assertIn("target contract is invalid", evidence["error"])


class TrustAnchorTests(unittest.TestCase):
    """Validator authority must be independent of the runtime under repair."""

    def test_release_owned_validator_is_not_an_authority(self) -> None:
        """The lane must not trust a file the repaired runtime could have written."""
        with patch.object(
            provenance_recovery, "_verified_trust_anchor",
            return_value={"verified": False, "reason": "anchor is missing",
                          "path": "/etc/grabowski/runtime-contract-schema.py",
                          "present": False, "sha256": None},
        ), patch.object(provenance_recovery, "_git_bytes") as git_bytes:
            git_bytes.side_effect = lambda repo, *args: b"x"
            evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertTrue(evidence["indeterminate"])
        self.assertIn("trust anchor", evidence["error"])
        self.assertFalse(evidence["contract_valid"])

    def test_running_validator_must_match_independent_anchor(self) -> None:
        trusted = (SRC / "grabowski_runtime_contract.py").read_bytes()
        contract = (ROOT / "config" / "runtime-entrypoint.json").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            drifted = Path(directory) / "grabowski_runtime_contract.py"
            drifted.write_bytes(b"# drifted running validator\n")
            with patch.object(
                provenance_recovery,
                "_verified_trust_anchor",
                return_value={
                    "verified": True, "reason": None, "present": True,
                    "path": "/etc/grabowski/runtime-contract-schema.py",
                    "sha256": "0" * 64, "source": trusted,
                },
            ), patch.object(provenance_recovery, "_git_bytes") as git_bytes, patch.object(
                provenance_recovery.runtime_contract, "__file__", str(drifted)
            ):
                git_bytes.side_effect = lambda repo, *args: (
                    contract if args[-1].endswith(".json") else trusted
                )
                evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertTrue(evidence["indeterminate"])
        self.assertFalse(evidence["contract_valid"])
        self.assertFalse(evidence["running_validator_matches_trust_anchor"])
        self.assertIn("running canonical validator", evidence["error"])

    def test_gate_is_closed_without_a_verified_anchor(self) -> None:
        """Fail closed: no independent authority means no authorisation."""
        case = ProvenanceRecoveryGateTests("run")
        case.setUp()
        gate = case._gate(
            target={
                "contract_valid": False,
                "validator_is_deployed": False,
                "indeterminate": True,
                "error": "no trust anchor",
            }
        )
        self.assertFalse(gate["allowed"])
        self.assertIn("target_schema_judgeable", gate["reasons"])

    def test_anchor_verification_rejects_symlinked_parent(self) -> None:
        target = provenance_recovery.TRUST_ANCHOR

        def fake_lstat(path):
            if path == target:
                return types.SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o644, st_nlink=1, st_uid=0
                )
            if path == target.parent:
                return types.SimpleNamespace(
                    st_mode=stat.S_IFLNK | 0o777, st_nlink=1, st_uid=0
                )
            return types.SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o755, st_nlink=1, st_uid=0
            )

        with patch.object(Path, "is_symlink", autospec=True, return_value=False), patch.object(
            Path, "lstat", autospec=True, side_effect=fake_lstat
        ):
            evidence = provenance_recovery._verified_trust_anchor(target)

        self.assertFalse(evidence["verified"])
        self.assertIn("parent", evidence["reason"])
        self.assertIn("symlink", evidence["reason"])

    def test_anchor_verification_rejects_unsafe_provenance(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            same_uid = Path(directory) / "schema.py"
            same_uid.write_text("x", encoding="utf-8")
            evidence = provenance_recovery._verified_trust_anchor(same_uid)
            self.assertFalse(evidence["verified"])
            self.assertIn("root-owned", evidence["reason"])

            link = Path(directory) / "link.py"
            link.symlink_to(same_uid)
            self.assertIn(
                "symlink", provenance_recovery._verified_trust_anchor(link)["reason"]
            )

            missing = provenance_recovery._verified_trust_anchor(
                Path(directory) / "absent"
            )
            self.assertFalse(missing["verified"])


class DispatchOutcomeTests(unittest.TestCase):
    """A started deployment must never be reported as not-having-happened."""

    def test_bookkeeping_failure_after_start_does_not_raise(self) -> None:
        """Post-dispatch failures become warnings, not a false 'it failed'."""
        gate = {
            "allowed": True,
            "reasons": [],
            "runtime_integrity": {"failed_integrity_flags": ["provenance_valid"]},
            "source_identity": _source_identity(ROOT),
        }
        calls = {"n": 0}

        def flaky_index_write(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] > 1:  # the post-start write
                raise OSError("disk full")

        with (
            patch.object(provenance_recovery, "evaluate_gate", return_value=gate),
            patch.object(
                provenance_recovery,
                "_volatile_gate_recheck",
                return_value={"reasons": [], "checks": {}},
            ),
            patch.object(provenance_recovery.base, "_append_audit_with_digest",
                         return_value="d" * 64),
            patch.object(provenance_recovery.base, "_require_valid_audit_chain"),
            patch.object(
                provenance_recovery.self_deploy,
                "_write_deploy_index",
                side_effect=flaky_index_write,
            ),
            patch.object(
                provenance_recovery.operator,
                "_start_job",
                return_value={"unit": "u", "argv_sha256": "b" * 64},
            ),
        ):
            receipt = provenance_recovery.grabowski_recovery_provenance_repair(HEAD)

        self.assertEqual(receipt["job"]["unit"], "u")
        self.assertTrue(receipt["post_dispatch_warnings"])
        self.assertIn("bookkeeping", receipt["post_dispatch_warnings"][0])

    def test_unknown_dispatch_outcome_keeps_the_reservation(self) -> None:
        """A job that may be running must not have its reservation released."""
        gate = {
            "allowed": True, "reasons": [],
            "runtime_integrity": {"failed_integrity_flags": ["provenance_valid"]},
            "source_identity": _source_identity(ROOT),
        }
        unknown = provenance_recovery.operator.JobDispatchUnknown(
            "unresolved", unit="grabowski-job-abc", evidence={"outcome": "outcome_unknown"}
        )
        with (
            patch.object(provenance_recovery, "evaluate_gate", return_value=gate),
            patch.object(provenance_recovery, "_volatile_gate_recheck",
                         return_value={"reasons": [], "checks": {}}),
            patch.object(provenance_recovery.base, "_append_audit_with_digest",
                         return_value="d" * 64),
            patch.object(provenance_recovery.base, "_require_valid_audit_chain"),
            patch.object(provenance_recovery.base, "_append_audit") as audit,
            patch.object(provenance_recovery.self_deploy, "_write_deploy_index") as index,
            patch.object(provenance_recovery.operator, "_start_job", side_effect=unknown),
        ):
            with self.assertRaises(provenance_recovery.operator.JobDispatchUnknown):
                provenance_recovery.grabowski_recovery_provenance_repair(HEAD)

        # Exactly one index write: the reservation.  It is never cleared.
        self.assertEqual(index.call_count, 1)
        self.assertEqual(
            audit.call_args[0][0]["operation"],
            "provenance-recovery-dispatch-outcome-unknown",
        )

    def test_receipt_carries_a_deterministic_correlation_id(self) -> None:
        """A caller that lost the response can correlate a retry with what ran."""
        gate = {
            "allowed": True,
            "reasons": [],
            "runtime_integrity": {"failed_integrity_flags": ["provenance_valid"]},
            "source_identity": _source_identity(ROOT),
        }
        seen = []
        for _ in range(2):
            with (
                patch.object(provenance_recovery, "evaluate_gate", return_value=gate),
                patch.object(
                    provenance_recovery,
                    "_volatile_gate_recheck",
                    return_value={"reasons": [], "checks": {}},
                ),
                patch.object(provenance_recovery.base, "_append_audit_with_digest",
                             return_value="d" * 64),
                patch.object(provenance_recovery.base, "_require_valid_audit_chain"),
                patch.object(provenance_recovery.self_deploy, "_write_deploy_index"),
                patch.object(
                    provenance_recovery.operator,
                    "_start_job",
                    return_value={"unit": "u", "argv_sha256": "b" * 64},
                ),
            ):
                seen.append(
                    provenance_recovery.grabowski_recovery_provenance_repair(HEAD)[
                        "repair_intent_id"
                    ]
                )

        self.assertEqual(seen[0], seen[1])
        self.assertEqual(len(seen[0]), 64)


class MidCutoverCompletionWarrantTests(unittest.TestCase):
    def _gate(self, *, phase: str, repair_warranted: bool, lane: str | None = None):
        selected_lane = lane or provenance_recovery.midcutover.LANE_MID_CUTOVER_RESUME
        recovery_lane = {
            "lane": selected_lane,
            "resume_binding": (
                {"binding_sha256": "ab" * 32, "resume_phase": phase}
                if selected_lane
                == provenance_recovery.midcutover.LANE_MID_CUTOVER_RESUME
                else None
            ),
            "reasons": [],
        }
        with (
            patch.object(
                provenance_recovery.base,
                "_verify_audit_log",
                return_value={"valid": True, "audit_writable": True},
            ),
            patch.object(
                provenance_recovery.base,
                "_kill_switch_state",
                return_value={"engaged": False},
            ),
            patch.object(
                provenance_recovery.privileged,
                "grabowski_privileged_broker_status",
                return_value={"ready": True},
            ),
            patch.object(
                provenance_recovery,
                "_integrity_evidence",
                return_value={"repair_warranted": repair_warranted},
            ),
            patch.object(
                provenance_recovery,
                "_blockade_evidence",
                return_value={"allows_mutation": True},
            ),
            patch.object(
                provenance_recovery,
                "_competing_deployment_evidence",
                return_value={
                    "deploy_lock_free": True,
                    "inflight_deploy_jobs": [],
                    "error": None,
                },
            ),
            patch.object(
                provenance_recovery, "_recovery_lane", return_value=recovery_lane
            ),
        ):
            return provenance_recovery.evaluate_resume_gate(HEAD)

    def test_start_warrant_opens_s0_only_while_integrity_is_invalid(self) -> None:
        opened = self._gate(
            phase=provenance_recovery.midcutover.PHASE_REBIND_SNAPSHOT,
            repair_warranted=True,
        )
        self.assertTrue(opened["allowed"])
        self.assertTrue(opened["start_warrant"])
        self.assertFalse(opened["completion_warrant"])

        closed = self._gate(
            phase=provenance_recovery.midcutover.PHASE_REBIND_SNAPSHOT,
            repair_warranted=False,
        )
        self.assertFalse(closed["allowed"])
        self.assertIn("start_or_completion_warrant", closed["reasons"])

    def test_completion_warrant_finishes_only_an_applied_lineage(self) -> None:
        for phase in (
            provenance_recovery.midcutover.PHASE_PROMOTE_POINTER,
            provenance_recovery.midcutover.PHASE_SELECT_CANONICAL,
            provenance_recovery.midcutover.PHASE_RETIRE_GREEN,
            provenance_recovery.midcutover.PHASE_CLOSEOUT,
        ):
            with self.subTest(phase=phase):
                gate = self._gate(phase=phase, repair_warranted=False)
                self.assertTrue(gate["allowed"], gate["reasons"])
                self.assertFalse(gate["start_warrant"])
                self.assertTrue(gate["completion_warrant"])

        foreign = self._gate(
            phase=provenance_recovery.midcutover.PHASE_CLOSEOUT,
            repair_warranted=False,
            lane=provenance_recovery.midcutover.LANE_FAIL_CLOSED,
        )
        self.assertFalse(foreign["allowed"])
        self.assertFalse(foreign["completion_warrant"])


class IntegrityStateTests(unittest.TestCase):
    """Unknown integrity is not a repair warrant."""

    def _state(self, metadata: dict) -> dict:
        with patch.object(
            provenance_recovery.base, "_deployment_metadata", return_value=metadata
        ):
            return provenance_recovery._integrity_evidence()

    def test_explicit_false_is_invalid_and_warrants_repair(self) -> None:
        state = self._state({k: True for k in provenance_recovery.REPAIRABLE_INTEGRITY_FLAGS}
                            | {"provenance_valid": False})
        self.assertEqual(state["integrity_state"], "invalid")
        self.assertTrue(state["repair_warranted"])

    def test_all_true_is_valid_and_warrants_nothing(self) -> None:
        state = self._state({k: True for k in provenance_recovery.REPAIRABLE_INTEGRITY_FLAGS})
        self.assertEqual(state["integrity_state"], "valid")
        self.assertFalse(state["repair_warranted"])

    def test_missing_flags_are_indeterminate_not_a_warrant(self) -> None:
        """A failed metadata probe must not authorise a deployment."""
        for metadata in ({}, {"provenance_valid": None}, {"provenance_valid": "unknown"}):
            with self.subTest(repr(metadata)):
                state = self._state(metadata)
                self.assertEqual(state["integrity_state"], "indeterminate")
                self.assertFalse(state["repair_warranted"])
                self.assertTrue(state["indeterminate_integrity_flags"])


class ToolSurfaceTests(unittest.TestCase):
    """The lane must stay two narrow tools, not a general authority."""

    def test_repair_does_not_expose_command_or_power_authority(self) -> None:
        """Checked over identifiers, so prose about the deadlock cannot trip it."""
        import ast

        tree = ast.parse(
            (SRC / "grabowski_provenance_recovery.py").read_text(encoding="utf-8")
        )
        identifiers = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                identifiers.add(node.id)
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr)

        forbidden = {
            "grabowski_power_run",
            "grabowski_terminal_run",
            "power_run",
            "terminal_run",
            "opaque_command",
            # _require_operator_mutation binds to the blockade *and* provenance
            # path this lane exists to repair; the plain capability check is a
            # restriction and is used deliberately.
            "_require_operator_mutation",
        }
        self.assertEqual(identifiers & forbidden, set())

    def test_repair_effect_is_limited_to_the_deployment_runner(self) -> None:
        source = (SRC / "grabowski_provenance_recovery.py").read_text(encoding="utf-8")

        self.assertIn("self_deploy._deploy_command(", source)
        self.assertIn("RUNNER_RELATIVE_PATH", source)


if __name__ == "__main__":
    unittest.main()


class IndexedInflightJobEvidenceGateTests(unittest.TestCase):
    """The recovery gate reports indexed in-flight jobs, not only reservations."""

    def test_gate_reports_indexed_jobs_as_competing(self) -> None:
        with patch.object(
            provenance_recovery.self_deploy,
            "inflight_runtime_job_evidence",
            return_value={
                "inflight_units": ["grabowski-job-444444444444"],
                "blocking_units": ["grabowski-job-444444444444"],
                "idempotent_match": None,
                "pruned_units": [],
                "error": None,
            },
            create=True,
        ):
            evidence = provenance_recovery._competing_deployment_evidence()
        self.assertEqual(
            evidence["inflight_deploy_jobs"], ["grabowski-job-444444444444"]
        )
        self.assertIsNone(evidence["idempotent_match"])

    def test_identical_running_intent_is_reported_as_idempotent(self) -> None:
        match = {"unit": "grabowski-job-555555555555", "kind": "deploy"}
        with patch.object(
            provenance_recovery.self_deploy,
            "inflight_runtime_job_evidence",
            return_value={
                "inflight_units": [match["unit"]],
                "blocking_units": [],
                "idempotent_match": match,
                "pruned_units": [],
                "error": None,
            },
            create=True,
        ):
            evidence = provenance_recovery._competing_deployment_evidence(["argv"])
        # Our own running intent must not read as a competitor...
        self.assertEqual(evidence["inflight_deploy_jobs"], [])
        # ...but it must be visible, so the dispatch can coalesce onto it.
        self.assertEqual(evidence["idempotent_match"], match)
