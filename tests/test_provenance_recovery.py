"""The provenance repair lane must open only on independent evidence.

Every check here guards the same invariant: a fail-closed integrity gate may
not close over its own repair path, but the escape hatch it needs must not
become a way around the gate for anything else.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
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
    self_deploy = types.ModuleType("grabowski_self_deploy")
    self_deploy.ExpectedHead = str
    self_deploy.SourceRepository = str
    self_deploy.SourceLeaseOwner = str
    self_deploy.RUNNER_RELATIVE_PATH = Path("tools/run_scheduled_deploy.py")
    self_deploy.DEPLOY_JOB_PREFIX = "grabowski-job-"
    self_deploy._deployment_source_preflight = lambda *args, **kwargs: None
    self_deploy._deploy_command = lambda *args, **kwargs: ["python3"]
    self_deploy._deploy_index = lambda root: {"units": [], "pending_unit": None}
    self_deploy._write_deploy_index = lambda *args, **kwargs: None

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
            "local_backup_fresh": {"backup": {"valid": False}},
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


class TargetContractEvidenceTests(unittest.TestCase):
    """The repair target is judged before it is ever built."""

    def test_current_repository_head_is_a_valid_repair_target(self) -> None:
        repository = ROOT
        head = provenance_recovery._git_bytes(
            repository, "rev-parse", "HEAD"
        )
        self.assertIsNotNone(head)
        evidence = provenance_recovery._target_contract_evidence(
            repository, head.decode().strip()
        )

        self.assertIsNone(evidence["error"])
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

    def test_invalid_target_contract_is_refused(self) -> None:
        """A target whose own schema rejects its own contract is not a repair."""
        validator = (SRC / "grabowski_runtime_contract.py").read_bytes()
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        contract["unreviewed_capability"] = True
        payload = json.dumps(contract).encode("utf-8")

        with patch.object(provenance_recovery, "_git_bytes") as git_bytes:
            git_bytes.side_effect = lambda repo, *args: (
                payload if args[-1].endswith(".json") else validator
            )
            evidence = provenance_recovery._target_contract_evidence(ROOT, HEAD)

        self.assertFalse(evidence["contract_valid"])
        self.assertIn("target contract is invalid", evidence["error"])


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
            "_require_operator_capability",
        }
        self.assertEqual(identifiers & forbidden, set())

    def test_repair_effect_is_limited_to_the_deployment_runner(self) -> None:
        source = (SRC / "grabowski_provenance_recovery.py").read_text(encoding="utf-8")

        self.assertIn("self_deploy._deploy_command(", source)
        self.assertIn("RUNNER_RELATIVE_PATH", source)


if __name__ == "__main__":
    unittest.main()
