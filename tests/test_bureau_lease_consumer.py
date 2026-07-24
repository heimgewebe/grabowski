from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
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

import grabowski_bureau_leases as bureau  # noqa: E402
import grabowski_resources as resources  # noqa: E402


class _BureauLeaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "state/resources.sqlite3"
        self.runtime = self.root / "bureau-runtime"
        self.release_commit = "b" * 40
        self.release = self.runtime / f"venv-{self.release_commit}"
        self.release.mkdir(parents=True)
        (self.runtime / "venv").symlink_to(self.release.name, target_is_directory=True)
        self.python = self.release / "bin/python3"
        self.python.parent.mkdir(parents=True)
        self.python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.python.chmod(0o700)
        self.executable_target = self.release / "bin/bureau"
        self.executable_target.write_text(
            f"#!{self.python}\nexit 0\n", encoding="utf-8"
        )
        self.executable_target.chmod(0o700)
        self.executable = self.runtime / "venv/bin/bureau"
        (self.release / "pyvenv.cfg").write_text(
            "home = /usr/bin\n", encoding="utf-8"
        )
        package = self.release / "lib/python3.10/site-packages/bureau"
        package.mkdir(parents=True)
        self.cli_module = package / "cli.py"
        self.cli_module.write_text("def main(argv=None): return 0\n", encoding="utf-8")
        self.lease_module = package / "lease_contract.py"
        self.lease_module.write_text("LEASE_CONTRACT_SCHEMA_VERSION = 2\n", encoding="utf-8")
        self.patches = [
            patch.object(resources, "RESOURCE_DB", self.database),
            patch.object(bureau, "BUREAU_RUNTIME_ROOT", self.runtime),
            patch.object(bureau, "BUREAU_CONTRACT_EXECUTABLE", self.executable),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def _response(
        self,
        argv: list[str],
        *,
        healthy: bool = True,
        schema_version: int = 2,
        findings: list[dict[str, object]] | None = None,
        enveloped: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        keys = [
            argv[index + 1]
            for index, value in enumerate(argv)
            if value == "--resource-key"
        ]
        phase = argv[argv.index("--phase") + 1]
        ttl = int(argv[argv.index("--ttl-seconds") + 1])
        expected_head = (
            argv[argv.index("--expected-head") + 1]
            if "--expected-head" in argv
            else None
        )
        expected_state = (
            argv[argv.index("--expected-state") + 1]
            if "--expected-state" in argv
            else None
        )
        payload = {
            "schema_version": schema_version,
            "kind": "bureau_lease_diagnostics",
            "phase": phase,
            "ttl_seconds": ttl,
            "resource_keys": sorted(keys),
            "healthy": healthy,
            "findings": findings or [],
            "required_merge_gate": bureau.BUREAU_MERGE_GATE_KEY,
            "required_worktree_admin_gate": bureau.BUREAU_WORKTREE_ADMIN_KEY,
            "global_repo_lease": bureau.BROAD_BUREAU_REPOSITORY_KEY,
            "justification_present": "--justification" in argv,
            "expected_head": expected_head,
            "expected_state": expected_state,
            "expected_boundary_present": bool(expected_head or expected_state),
        }
        if enveloped:
            payload = {
                "schema_version": 1,
                "result": payload,
                "runtime_identity": {
                    "schema_version": 1,
                    "kind": "bureau_runtime_identity",
                    "manifest": {
                        "valid": True,
                        "source_commit": self.release_commit,
                    },
                    "registry": {
                        "available": True,
                        "bureau_project": True,
                        "dirty": False,
                        "role": "canonical-runtime-snapshot",
                        "head_equals_origin_main": True,
                        "head": self.release_commit,
                        "origin_main": self.release_commit,
                    },
                },
            }
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")


class BureauLeaseConsumerTests(_BureauLeaseTestCase):
    def test_non_bureau_resource_does_not_invoke_contract(self) -> None:
        with patch.object(bureau.subprocess, "run") as run:
            result = resources.acquire_resources(
                "owner-a", ["repo:/tmp/other"], purpose="other", ttl_seconds=60
            )
        run.assert_not_called()
        self.assertIsNone(result["bureau_contract"])

    def test_exact_task_paths_can_be_acquired_by_different_owners(self) -> None:
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            first = resources.acquire_resources(
                "owner-a",
                ["path:/home/alex/repos/bureau/registry/tasks/A-T001.json"],
                purpose="task A",
                ttl_seconds=60,
            )
            second = resources.acquire_resources(
                "owner-b",
                ["path:/home/alex/repos/bureau/registry/tasks/B-T001.json"],
                purpose="task B",
                ttl_seconds=60,
            )
        self.assertEqual(first["bureau_contract"]["phase"], "work")
        self.assertEqual(second["bureau_contract"]["phase"], "work")
        self.assertEqual(len(resources.list_resources()), 2)

    def test_runtime_envelope_is_unwrapped_before_contract_validation(self) -> None:
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(
                argv, enveloped=True
            ),
        ):
            result = resources.acquire_resources(
                "owner-a",
                ["path:/home/alex/repos/bureau/registry/tasks/A-T001.json"],
                purpose="task A",
                ttl_seconds=60,
            )
        self.assertEqual(result["bureau_contract"]["phase"], "work")
        self.assertEqual(
            result["bureau_contract"]["contract_release_commit"],
            self.release_commit,
        )
        self.assertEqual(len(resources.list_resources()), 1)

    def test_runtime_envelope_rejects_unexpected_top_level_fields(self) -> None:
        def response(argv: list[str], **kwargs):
            result = self._response(argv, enveloped=True)
            value = json.loads(result.stdout)
            value["unexpected"] = True
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

        with patch.object(bureau.subprocess, "run", side_effect=response):
            with self.assertRaises(bureau.BureauLeaseContractError) as raised:
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertEqual(raised.exception.code, "contract-envelope-shape-invalid")
        self.assertFalse(self.database.exists())

    def test_runtime_envelope_rejects_dirty_registry_identity(self) -> None:
        def response(argv: list[str], **kwargs):
            result = self._response(argv, enveloped=True)
            value = json.loads(result.stdout)
            value["runtime_identity"]["registry"]["dirty"] = True
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

        with patch.object(bureau.subprocess, "run", side_effect=response):
            with self.assertRaises(bureau.BureauLeaseContractError) as raised:
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertEqual(raised.exception.code, "contract-runtime-registry-invalid")
        self.assertFalse(self.database.exists())

    def test_contract_failure_happens_before_database_mutation(self) -> None:
        failed = subprocess.CompletedProcess(["bureau"], 2, "", "sensitive reason")
        with patch.object(bureau.subprocess, "run", return_value=failed):
            with self.assertRaises(bureau.BureauLeaseContractError) as raised:
                resources.acquire_resources(
                    "owner-a",
                    ["repo:/home/alex/repos/bureau"],
                    purpose="forbidden",
                    ttl_seconds=60,
                )
        self.assertEqual(raised.exception.code, "contract-command-failed")
        self.assertNotIn("sensitive reason", str(raised.exception))
        self.assertFalse(self.database.exists())

    def test_unhealthy_contract_does_not_create_row(self) -> None:
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(
                argv,
                healthy=False,
                findings=[{"code": "broad-bureau-repo-lease-forbidden"}],
            ),
        ):
            with self.assertRaises(bureau.BureauLeaseContractError) as raised:
                resources.acquire_resources(
                    "owner-a",
                    ["repo:/home/alex/repos/bureau"],
                    purpose="forbidden",
                    ttl_seconds=60,
                )
        self.assertEqual(raised.exception.code, "contract-unhealthy")
        self.assertEqual(
            raised.exception.details["finding_codes"],
            ["broad-bureau-repo-lease-forbidden"],
        )
        self.assertFalse(self.database.exists())

    def test_schema_mismatch_fails_closed(self) -> None:
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv, schema_version=1),
        ):
            with self.assertRaisesRegex(RuntimeError, "schema-version-mismatch"):
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertFalse(self.database.exists())

    def test_contract_resource_set_must_match(self) -> None:
        def mismatch(argv: list[str], **kwargs):
            result = self._response(argv)
            value = json.loads(result.stdout)
            value["resource_keys"] = []
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

        with patch.object(bureau.subprocess, "run", side_effect=mismatch):
            with self.assertRaisesRegex(RuntimeError, "resource-set-mismatch"):
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertFalse(self.database.exists())

    def test_merge_gate_infers_phase_and_passes_ttl(self) -> None:
        observed: list[list[str]] = []

        def response(argv: list[str], **kwargs):
            observed.append(argv)
            return self._response(argv)

        with patch.object(bureau.subprocess, "run", side_effect=response):
            result = resources.acquire_resources(
                "owner-a",
                [bureau.BUREAU_MERGE_GATE_KEY],
                purpose="merge",
                ttl_seconds=120,
            )
        self.assertEqual(result["bureau_contract"]["phase"], "merge")
        self.assertIn("120", observed[0])

    def test_emergency_metadata_is_forwarded_but_not_returned(self) -> None:
        observed: list[list[str]] = []

        def response(argv: list[str], **kwargs):
            observed.append(argv)
            return self._response(argv)

        metadata = {
            "bureau_phase": "emergency-recovery",
            "bureau_justification": "private recovery reason",
            "bureau_expected_head": "a" * 40,
        }
        with patch.object(bureau.subprocess, "run", side_effect=response):
            result = resources.acquire_resources(
                "owner-a",
                [bureau.BROAD_BUREAU_REPOSITORY_KEY],
                purpose="recovery",
                ttl_seconds=300,
                metadata=metadata,
            )
        self.assertNotIn("private recovery reason", observed[0])
        self.assertIn(
            "sha256:"
            + hashlib.sha256(b"private recovery reason").hexdigest(),
            observed[0],
        )
        self.assertNotIn("private recovery reason", json.dumps(result))
        self.assertEqual(result["bureau_contract"]["phase"], "emergency-recovery")
        import sqlite3
        with sqlite3.connect(self.database) as connection:
            stored = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?",
                (bureau.BROAD_BUREAU_REPOSITORY_KEY,),
            ).fetchone()[0]
        self.assertNotIn("private recovery reason", stored)
        self.assertIn("sha256:", stored)

    def test_audit_contains_only_contract_summary(self) -> None:
        metadata = {
            "lease_mode": "emergency-recovery",
            "bureau_phase": "emergency-recovery",
            "bureau_justification": "private recovery reason",
            "bureau_expected_state": "expected clean state",
        }
        with (
            patch.object(
                bureau.subprocess,
                "run",
                side_effect=lambda argv, **kwargs: self._response(argv),
            ),
            patch.object(resources.operator, "_require_operator_mutation"),
            patch.object(resources.base, "_append_audit") as audit,
        ):
            resources.grabowski_resource_acquire(
                "owner-a",
                [bureau.BROAD_BUREAU_REPOSITORY_KEY],
                "recovery",
                300,
                metadata,
            )
        encoded = json.dumps(audit.call_args.args[0])
        self.assertNotIn("private recovery reason", encoded)
        self.assertIn("contract_stdout_sha256", encoded)

    def test_contract_hash_is_bound_to_executable(self) -> None:
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            result = resources.acquire_resources(
                "owner-a",
                ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                purpose="task",
                ttl_seconds=60,
            )
        self.assertEqual(
            result["bureau_contract"]["contract_executable_sha256"],
            hashlib.sha256(self.executable.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            result["bureau_contract"]["contract_release_commit"],
            self.release_commit,
        )
        components = result["bureau_contract"]["contract_component_sha256"]
        self.assertEqual(
            components["bureau_lease_contract"],
            hashlib.sha256(self.lease_module.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            components["bureau_cli"],
            hashlib.sha256(self.cli_module.read_bytes()).hexdigest(),
        )

    def test_contract_runs_bound_interpreter_in_isolated_mode(self) -> None:
        observed: list[list[str]] = []

        def response(argv: list[str], **kwargs):
            observed.append(argv)
            return self._response(argv)

        with patch.object(bureau.subprocess, "run", side_effect=response):
            resources.acquire_resources(
                "owner-a",
                ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                purpose="task",
                ttl_seconds=60,
            )
        self.assertEqual(observed[0][0], str(self.python))
        self.assertEqual(observed[0][1:3], ["-I", "-c"])

    def test_contract_output_must_bind_canonical_gate_keys(self) -> None:
        def mismatch(argv: list[str], **kwargs):
            result = self._response(argv)
            payload = json.loads(result.stdout)
            payload["required_merge_gate"] = "path:/tmp/wrong"
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

        with patch.object(bureau.subprocess, "run", side_effect=mismatch):
            with self.assertRaisesRegex(RuntimeError, "merge-gate-mismatch"):
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertFalse(self.database.exists())


class BureauManagedRuntimeTests(_BureauLeaseTestCase):
    def _install_managed_runtime(self) -> tuple[Path, str, list[object]]:
        source_commit = "c" * 40
        release_id = f"{source_commit[:12]}-src123456789abc"
        release = self.runtime / "releases" / release_id
        package = release / "src/bureau"
        package.mkdir(parents=True)
        (release / "pyproject.toml").write_text(
            "[project]\nname = 'bureau'\nversion = '0.2.1'\n", encoding="utf-8"
        )
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "cli.py").write_text(
            "def main(argv=None): return 0\n", encoding="utf-8"
        )
        (package / "lease_contract.py").write_text(
            "LEASE_CONTRACT_SCHEMA_VERSION = 2\n", encoding="utf-8"
        )
        module = package / "runtime_identity.py"
        module.write_text("SCHEMA_VERSION = 1\n", encoding="utf-8")
        package_paths = bureau._managed_package_paths(release)
        package_digest = bureau._managed_package_tree_sha256(package_paths)
        snapshot = self.runtime / "registry-snapshots" / "current"
        snapshot.mkdir(parents=True)
        inventory = snapshot / ".bureau-runtime-snapshot.json"
        inventory.write_text("{}\n", encoding="utf-8")
        launcher = self.root / "bin/bureau"
        launcher.parent.mkdir(parents=True)
        manifest = {
            "schema_version": 1,
            "kind": "bureau_runtime_deployment",
            "release_id": release_id,
            "source_commit": source_commit,
            "package_tree_sha256": package_digest,
            "immutable_release_path": str(release),
            "module_path": str(module),
            "module_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
            "canonical_registry_root": str(snapshot),
            "canonical_registry_inventory_path": str(inventory),
            "launcher_path": str(launcher),
        }
        manifest_path = self.runtime / "deployment-manifest.json"
        manifest_raw = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        manifest_path.write_bytes(manifest_raw)
        manifest_digest = hashlib.sha256(manifest_raw).hexdigest()
        launcher.write_text(
            "#!/usr/bin/env python3\n"
            "# managed-by: heimgewebe-bureau-runtime-v1\n"
            f"expected_manifest_sha256 = '{manifest_digest}'\n",
            encoding="utf-8",
        )
        launcher.chmod(0o700)
        patches = [
            patch.object(bureau, "BUREAU_MANAGED_LAUNCHER", launcher),
            patch.object(bureau, "BUREAU_CONTRACT_PYTHON", self.python),
        ]
        return launcher, source_commit, patches

    def test_managed_runtime_is_preferred_and_invoked_via_bound_fd(self) -> None:
        launcher, source_commit, patches = self._install_managed_runtime()
        observed: list[tuple[list[str], dict[str, object]]] = []

        def response(argv: list[str], **kwargs):
            observed.append((argv, kwargs))
            return self._response(argv)

        with (
            patches[0],
            patches[1],
            patch.object(bureau.subprocess, "run", side_effect=response),
        ):
            result = resources.acquire_resources(
                "owner-a",
                ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                purpose="task",
                ttl_seconds=60,
            )
        argv, kwargs = observed[0]
        self.assertEqual(argv[0], str(self.python.resolve()))
        self.assertEqual(argv[1], "-I")
        self.assertRegex(argv[2], r"^/proc/self/fd/[0-9]+$")
        self.assertEqual(
            tuple(kwargs["pass_fds"]),
            (int(argv[2].rsplit("/", 1)[1]),),
        )
        self.assertIn("lease-contract", argv)
        self.assertEqual(
            result["bureau_contract"]["contract_release_commit"], source_commit
        )
        self.assertEqual(
            result["bureau_contract"]["contract_executable_sha256"],
            hashlib.sha256(launcher.read_bytes()).hexdigest(),
        )

    def test_managed_launcher_must_bind_exact_manifest(self) -> None:
        launcher, _source_commit, patches = self._install_managed_runtime()
        launcher.write_text(
            "#!/usr/bin/env python3\n"
            "# managed-by: heimgewebe-bureau-runtime-v1\n"
            "expected_manifest_sha256 = '" + "0" * 64 + "'\n",
            encoding="utf-8",
        )
        launcher.chmod(0o700)
        with patches[0], patches[1], patch.object(bureau.subprocess, "run") as run:
            with self.assertRaises(bureau.BureauLeaseContractError) as raised:
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertEqual(
            raised.exception.code, "contract-managed-launcher-binding-invalid"
        )
        run.assert_not_called()
        self.assertFalse(self.database.exists())

    def test_managed_package_drift_fails_before_invocation(self) -> None:
        _launcher, _source_commit, patches = self._install_managed_runtime()
        release = self.runtime / "releases" / ("c" * 12 + "-src123456789abc")
        (release / "src/bureau/cli.py").write_text(
            "def main(argv=None): return 1\n", encoding="utf-8"
        )
        with patches[0], patches[1], patch.object(bureau.subprocess, "run") as run:
            with self.assertRaises(bureau.BureauLeaseContractError) as raised:
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertEqual(
            raised.exception.code, "contract-managed-package-digest-invalid"
        )
        run.assert_not_called()
        self.assertFalse(self.database.exists())

    def test_managed_package_addition_during_check_fails_closed(self) -> None:
        _launcher, _source_commit, patches = self._install_managed_runtime()
        release = self.runtime / "releases" / ("c" * 12 + "-src123456789abc")

        def mutate(argv: list[str], **kwargs):
            result = self._response(argv)
            (release / "src/bureau/added.py").write_text(
                "VALUE = 1\n", encoding="utf-8"
            )
            return result

        with (
            patches[0],
            patches[1],
            patch.object(bureau.subprocess, "run", side_effect=mutate),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "package-set-changed-during-check"
            ):
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertFalse(self.database.exists())


def _insert_lease_without_contract(
    database: Path,
    *,
    resource_key: str,
    owner_id: str = "owner-a",
) -> None:
    import time

    database.parent.mkdir(parents=True, exist_ok=True)
    with resources._database() as connection:
        now = int(time.time())
        connection.execute(
            """
            INSERT INTO leases(
                resource_key, owner_id, purpose, acquired_at_unix,
                updated_at_unix, expires_at_unix, metadata_sha256,
                metadata_json, reclaimed_from_owner
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                resource_key,
                owner_id,
                "legacy",
                now,
                now,
                now + 3600,
                hashlib.sha256(b"{}").hexdigest(),
                "{}",
                None,
            ),
        )


class BureauLeaseRenewalTests(_BureauLeaseTestCase):
    def test_existing_broad_lease_cannot_be_renewed(self) -> None:
        _insert_lease_without_contract(
            self.database,
            resource_key=bureau.BROAD_BUREAU_REPOSITORY_KEY,
        )
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(
                argv,
                healthy=False,
                findings=[{"code": "broad-bureau-repo-lease-forbidden"}],
            ),
        ):
            with self.assertRaises(bureau.BureauLeaseContractError):
                resources.renew_resources(
                    "owner-a", [bureau.BROAD_BUREAU_REPOSITORY_KEY], ttl_seconds=60
                )
        lease = resources.inspect_resource(bureau.BROAD_BUREAU_REPOSITORY_KEY)
        self.assertIsNotNone(lease)
        self.assertEqual(lease["purpose"], "legacy")

    def test_exact_path_renewal_is_contract_bound(self) -> None:
        key = "path:/home/alex/repos/bureau/registry/tasks/A.json"
        _insert_lease_without_contract(self.database, resource_key=key)
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            result = resources.renew_resources("owner-a", [key], ttl_seconds=60)
        self.assertEqual(result["bureau_contract"]["phase"], "work")

    def test_effect_gates_cannot_be_renewed(self) -> None:
        for key in (bureau.BUREAU_MERGE_GATE_KEY, bureau.BUREAU_WORKTREE_ADMIN_KEY):
            _insert_lease_without_contract(self.database, resource_key=key)
            with patch.object(bureau.subprocess, "run") as run:
                with self.assertRaisesRegex(
                    RuntimeError, "effect-lease-renewal-forbidden"
                ):
                    resources.renew_resources("owner-a", [key], ttl_seconds=120)
            run.assert_not_called()
            resources.release_resources("owner-a", [key])

    def test_mixed_effect_gates_are_rejected_before_invocation(self) -> None:
        with patch.object(bureau.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "mixed-effect-gates-forbidden"):
                resources.acquire_resources(
                    "owner-a",
                    [bureau.BUREAU_MERGE_GATE_KEY, bureau.BUREAU_WORKTREE_ADMIN_KEY],
                    purpose="invalid mixed effect",
                    ttl_seconds=120,
                )
        run.assert_not_called()
        self.assertFalse(self.database.exists())

    def test_effect_gate_cannot_be_extended_by_reacquire(self) -> None:
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            resources.acquire_resources(
                "owner-a",
                [bureau.BUREAU_MERGE_GATE_KEY],
                purpose="merge",
                ttl_seconds=120,
            )
            before = resources.inspect_resource(bureau.BUREAU_MERGE_GATE_KEY)
            with self.assertRaises(resources.ResourceConflict):
                resources.acquire_resources(
                    "owner-a",
                    [bureau.BUREAU_MERGE_GATE_KEY],
                    purpose="merge again",
                    ttl_seconds=300,
                )
        after = resources.inspect_resource(bureau.BUREAU_MERGE_GATE_KEY)
        self.assertEqual(after["expires_at_unix"], before["expires_at_unix"])
        self.assertEqual(after["purpose"], "merge")


class BureauEmergencyConflictTests(_BureauLeaseTestCase):
    def test_legacy_broad_lease_does_not_block_exact_scope(self) -> None:
        _insert_lease_without_contract(
            self.database,
            resource_key=bureau.BROAD_BUREAU_REPOSITORY_KEY,
            owner_id="legacy-owner",
        )
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            result = resources.acquire_resources(
                "exact-owner",
                ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                purpose="exact task",
                ttl_seconds=60,
            )
        self.assertEqual(result["owner_id"], "exact-owner")

    def test_emergency_broad_lease_blocks_foreign_exact_scope(self) -> None:
        key = bureau.BROAD_BUREAU_REPOSITORY_KEY
        _insert_lease_without_contract(
            self.database,
            resource_key=key,
            owner_id="recovery-owner",
        )
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET metadata_json=? WHERE resource_key=?",
                (json.dumps({"bureau_phase": "emergency-recovery"}), key),
            )
            connection.commit()
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            with self.assertRaises(resources.ResourceConflict) as raised:
                resources.acquire_resources(
                    "exact-owner",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="exact task",
                    ttl_seconds=60,
                )
        self.assertEqual(raised.exception.resource_key, key)

    def test_emergency_broad_lease_cannot_start_over_foreign_exact_scope(self) -> None:
        exact = "path:/home/alex/repos/bureau/registry/tasks/A.json"
        _insert_lease_without_contract(
            self.database,
            resource_key=exact,
            owner_id="exact-owner",
        )
        metadata = {
            "bureau_phase": "emergency-recovery",
            "bureau_justification": "recover shared Git metadata",
            "bureau_expected_head": "a" * 40,
        }
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            with self.assertRaises(resources.ResourceConflict) as raised:
                resources.acquire_resources(
                    "recovery-owner",
                    [bureau.BROAD_BUREAU_REPOSITORY_KEY],
                    purpose="recovery",
                    ttl_seconds=300,
                    metadata=metadata,
                )
        self.assertEqual(raised.exception.resource_key, exact)
        self.assertIsNone(resources.inspect_resource(bureau.BROAD_BUREAU_REPOSITORY_KEY))

    def test_emergency_is_exclusive_against_same_owner_exact_scope(self) -> None:
        exact = "path:/home/alex/repos/bureau/registry/tasks/A.json"
        _insert_lease_without_contract(
            self.database,
            resource_key=exact,
            owner_id="same-owner",
        )
        metadata = {
            "bureau_phase": "emergency-recovery",
            "bureau_justification": "recover shared Git metadata",
            "bureau_expected_head": "a" * 40,
        }
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            with self.assertRaises(resources.ResourceConflict) as raised:
                resources.acquire_resources(
                    "same-owner",
                    [bureau.BROAD_BUREAU_REPOSITORY_KEY],
                    purpose="recovery",
                    ttl_seconds=300,
                    metadata=metadata,
                )
        self.assertEqual(raised.exception.resource_key, exact)

    def test_same_owner_cannot_acquire_exact_scope_during_emergency(self) -> None:
        broad = bureau.BROAD_BUREAU_REPOSITORY_KEY
        _insert_lease_without_contract(
            self.database,
            resource_key=broad,
            owner_id="same-owner",
        )
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET metadata_json=? WHERE resource_key=?",
                (json.dumps({"bureau_phase": "emergency-recovery"}), broad),
            )
            connection.commit()
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            with self.assertRaises(resources.ResourceConflict) as raised:
                resources.acquire_resources(
                    "same-owner",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="exact task",
                    ttl_seconds=60,
                )
        self.assertEqual(raised.exception.resource_key, broad)

    def test_exact_scope_renewal_is_blocked_by_foreign_emergency(self) -> None:
        exact = "path:/home/alex/repos/bureau/registry/tasks/A.json"
        broad = bureau.BROAD_BUREAU_REPOSITORY_KEY
        _insert_lease_without_contract(
            self.database,
            resource_key=exact,
            owner_id="exact-owner",
        )
        _insert_lease_without_contract(
            self.database,
            resource_key=broad,
            owner_id="recovery-owner",
        )
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET metadata_json=? WHERE resource_key=?",
                (json.dumps({"bureau_phase": "emergency-recovery"}), broad),
            )
            connection.commit()
        with patch.object(
            bureau.subprocess,
            "run",
            side_effect=lambda argv, **kwargs: self._response(argv),
        ):
            with self.assertRaises(resources.ResourceConflict):
                resources.renew_resources("exact-owner", [exact], ttl_seconds=60)


class BureauContractIntegrityTests(_BureauLeaseTestCase):
    def test_environment_cannot_redirect_canonical_bureau_roots(self) -> None:
        import inspect

        source = inspect.getsource(bureau)
        self.assertNotIn("GRABOWSKI_BUREAU_", source)
        self.assertIn(
            'BUREAU_REPOSITORY_ROOT = Path("/home/alex/repos/bureau")',
            source,
        )
        self.assertIn(
            'BUREAU_RUNTIME_ROOT = Path("/home/alex/.local/share/bureau")',
            source,
        )

    def test_contract_module_change_during_check_fails_closed(self) -> None:
        original = self.lease_module.read_bytes()

        def mutate(argv: list[str], **kwargs):
            result = self._response(argv)
            self.lease_module.write_bytes(original + b"# changed\n")
            return result

        with patch.object(bureau.subprocess, "run", side_effect=mutate):
            with self.assertRaisesRegex(RuntimeError, "component-changed-during-check"):
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertFalse(self.database.exists())

    def test_unversioned_contract_release_is_rejected_before_invocation(self) -> None:
        invalid_release = self.runtime / "venv-current"
        invalid_executable = invalid_release / "bin/bureau"
        invalid_executable.parent.mkdir(parents=True)
        invalid_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        invalid_executable.chmod(0o700)
        with (
            patch.object(bureau, "BUREAU_CONTRACT_EXECUTABLE", invalid_executable),
            patch.object(bureau.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "release-path-invalid"):
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        run.assert_not_called()
        self.assertFalse(self.database.exists())

    def test_executable_change_during_contract_check_fails_closed(self) -> None:
        original = self.executable.read_bytes()

        def mutate(argv: list[str], **kwargs):
            result = self._response(argv)
            self.executable.write_bytes(original + b"# changed\n")
            self.executable.chmod(0o700)
            return result

        with patch.object(bureau.subprocess, "run", side_effect=mutate):
            with self.assertRaisesRegex(RuntimeError, "changed-during-check"):
                resources.acquire_resources(
                    "owner-a",
                    ["path:/home/alex/repos/bureau/registry/tasks/A.json"],
                    purpose="task",
                    ttl_seconds=60,
                )
        self.assertFalse(self.database.exists())


if __name__ == "__main__":
    unittest.main()
