from __future__ import annotations

from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
HELPER_PATH = ROOT / "tools" / "grabowski_critical_user_data_inventory.py"
BROKER_PATH = ROOT / "src" / "grabowski_privileged_broker.py"
PRIVILEGED_PATH = ROOT / "src" / "grabowski_privileged.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{name} could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = _load("grabowski_critical_user_data_inventory_test", HELPER_PATH)
broker = _load("grabowski_privileged_broker_inventory_test", BROKER_PATH)
privileged = _load("grabowski_privileged_inventory_test", PRIVILEGED_PATH)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def _target(
    operation: str,
    *,
    scanner_sha256: str | None = None,
    contract_sha256: str | None = None,
) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": operation,
            "scanner_sha256": scanner_sha256 or helper.AUTHORIZED_SCANNER_SHA256,
            "contract_sha256": contract_sha256 or helper.AUTHORIZED_CONTRACT_SHA256,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _action() -> dict[str, object]:
    config = json.loads(
        (ROOT / "config" / "privileged-actions.example.json").read_text(
            encoding="utf-8"
        )
    )
    return config["actions"]["critical_user_data_inventory"]


def _home_contract() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": helper.SCOPE_KIND,
        "scope": "critical-user-data-home",
        "scope_semantics": "explicit-path-set",
        "root": "/home/alex",
        "logical_root": "/home/alex",
        "inventory": {
            "schema": "heim_pc.critical_user_data_inventory.v1",
            "algorithm": "canonical-record-stream-sha256-v7",
            "same_filesystem_only": True,
            "follow_symlinks": False,
            "regular_file_content_sha256": True,
            "directory_mode_bound": True,
            "regular_file_mode_bound": True,
            "uid_gid_bound": True,
            "explicit_ancestor_metadata_bound": True,
            "symlink_target_bound": True,
            "special_files": "excluded-runtime-only",
            "unreadable_included_path": "fail",
            "changed_during_hash": "fail",
            "authoritative_source_stability": helper.SOURCE_STABILITY_MODE,
        },
        "includes": [
            {
                "path": "/home/alex/.ssh",
                "class": "credentials-and-identity",
                "rationale": "fixture",
                "capture": "tree",
                "restore_mode": "active-user-data",
            }
        ],
        "exclusions": {
            "top_level_prefixes": [],
            "roots": [],
            "file_name_prefixes_under": [],
            "file_name_prefix_suffixes_under": [],
            "directory_names_under": [],
        },
    }


def _aggregate_contract(
    root_sha: str,
    aggregate_sha: str,
    home_sha: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": helper.SCOPE_KIND,
        "scope": "critical-user-data",
        "scope_semantics": helper.SCOPE_SEMANTICS,
        "members": [
            {
                "id": "home",
                "contract_file": "critical-user-home-data-contract-v1.json",
                "contract_sha256": home_sha,
                "destination": {
                    "nixos_storage_domain": "per-entry-policy",
                    "logical_path": "materialization-policy",
                },
                "restore_mode": "source-scope-with-role-specific-materialization",
            }
        ],
        "inventory_implementation": {
            "algorithm": helper.INVENTORY_ALGORITHM,
            "root_inventory_script": "scripts/nixos_critical_user_data_inventory.py",
            "root_inventory_script_sha256": root_sha,
            "aggregate_inventory_script": "scripts/nixos_critical_data_inventory.py",
            "aggregate_inventory_script_sha256": aggregate_sha,
            "aggregate_execution_mode": helper.AGGREGATE_EXECUTION_MODE,
            "member_contract_digest_bound": True,
            "source_and_restored_aggregate_inventory_sha256_must_match": True,
            "authoritative_member_source_stability": helper.SOURCE_STABILITY_MODE,
        },
        "migration_policy": {
            "selection_model": "explicit-positive-allowlist",
            "legacy_docker_volume_tree_migrated": False,
        },
    }


def _recovery_contract(aggregate_sha: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "heim_pc.nixos_recovery_readiness_contract",
        "critical_user_data_scope": {
            "contract_kind": helper.SCOPE_KIND,
            "scope": "critical-user-data",
            "sha256": aggregate_sha,
            "aggregate_member_contracts_bound": True,
            "off_host_restore_inventory_sha256_equality_required": True,
        },
    }


def _aggregate_inventory(
    *,
    contract_sha256: str,
    home_contract_sha256: str,
    home_inventory_sha256: str = "1" * 64,
) -> dict[str, object]:
    member = {
        "id": "home",
        "scope": "critical-user-data-home",
        "contract_sha256": home_contract_sha256,
        "inventory_sha256": home_inventory_sha256,
        "record_count": 7,
        "regular_file_bytes": 1234,
        "exclusion_boundary_count": 2,
    }
    aggregate_sha = _sha(
        _canonical(
            {
                "id": "home",
                "contract_sha256": home_contract_sha256,
                "inventory_sha256": home_inventory_sha256,
            }
        )
    )
    return {
        "schema_version": 1,
        "kind": helper.INVENTORY_KIND,
        "scope": "critical-user-data",
        "scope_semantics": helper.SCOPE_SEMANTICS,
        "algorithm": helper.INVENTORY_ALGORITHM,
        "critical_scope_sha256": contract_sha256,
        "contract_sha256": contract_sha256,
        "authoritative_inventory": True,
        "inventory_sha256": aggregate_sha,
        "member_count": 1,
        "members": [member],
        "record_count": member["record_count"],
        "regular_file_bytes": member["regular_file_bytes"],
        "exclusion_boundary_count": member["exclusion_boundary_count"],
        "production_effects_authorized": False,
    }


class CriticalUserDataInventoryPrivilegedTests(unittest.TestCase):
    def setUp(self) -> None:
        helper._apply_binding(
            helper.AUTHORIZED_SCANNER_SHA256,
            helper.AUTHORIZED_CONTRACT_SHA256,
        )

    def test_action_accepts_only_canonical_typed_requests(self) -> None:
        action = _action()
        config = {"actions": {"critical_user_data_inventory": action}}
        for operation in ("start", "status", "result"):
            with self.subTest(operation=operation):
                target = _target(operation)
                execution = broker.resolve_regular_execution(
                    config,
                    {
                        "action": "critical_user_data_inventory",
                        "target": target,
                    },
                )
                self.assertEqual(execution["mode"], "template")
                self.assertEqual(
                    execution["argv"],
                    [
                        "/usr/local/libexec/grabowski-critical-user-data-inventory",
                        target,
                    ],
                )
                self.assertEqual(execution["timeout_seconds"], 90)
                self.assertEqual(execution["allowed_peer_uid"], 1000)
                self.assertEqual(
                    execution["allowed_peer_unit"], "grabowski-operator.service"
                )

    def test_execute_is_not_reachable_through_broker(self) -> None:
        with self.assertRaises(PermissionError):
            broker.resolve_regular_execution(
                {"actions": {"critical_user_data_inventory": _action()}},
                {
                    "action": "critical_user_data_inventory",
                    "target": _target("execute"),
                },
            )

    def test_request_rejects_wrong_digest_shapes_and_extra_fields(self) -> None:
        config = {"actions": {"critical_user_data_inventory": _action()}}
        bad_requests = [
            _target("start", scanner_sha256="0" * 63),
            _target("start", contract_sha256="0" * 63),
            '{"operation":"start"}',
        ]
        for extra in (
            {"scanner_path": "/tmp/inventory.py"},
            {"contract_path": "/tmp/contract.json"},
            {"classification_only": True},
            {"max_exclusion_samples": 1},
            {"argv": ["/bin/sh"]},
            {"shell": "/bin/sh"},
        ):
            request = json.loads(_target("start"))
            request.update(extra)
            bad_requests.append(
                json.dumps(request, sort_keys=True, separators=(",", ":"))
            )
        for target in bad_requests:
            with self.subTest(target=target):
                with self.assertRaises(PermissionError):
                    broker.resolve_regular_execution(
                        config,
                        {
                            "action": "critical_user_data_inventory",
                            "target": target,
                        },
                    )

    def test_action_is_not_generic_root_authority(self) -> None:
        action = _action()
        self.assertEqual(action["mode"], "template")
        self.assertEqual(
            action["argv"],
            [
                "/usr/local/libexec/grabowski-critical-user-data-inventory",
                "{target}",
            ],
        )
        serialized = json.dumps(action, sort_keys=True)
        for forbidden in (
            "allowed_argv_prefixes",
            "allow_shell",
            "cwd_pattern",
            "/bin/sh",
            "/dev/disk/",
        ):
            self.assertNotIn(forbidden, serialized)


    def test_source_paths_and_commit_authority_are_fixed(self) -> None:
        expected_root = Path("/home/alex/repos/heim-pc")
        self.assertEqual(helper.SOURCE_ROOT, expected_root)
        self.assertEqual(
            helper.SCANNER_SOURCE,
            expected_root / "scripts/nixos_critical_user_data_inventory.py",
        )
        self.assertEqual(
            helper.AGGREGATE_SCANNER_SOURCE,
            expected_root / "scripts/nixos_critical_data_inventory.py",
        )
        self.assertEqual(
            helper.CONTRACT_SOURCE,
            expected_root / "nixos/production/critical-user-data-contract-v1.json",
        )
        self.assertEqual(
            helper.HOME_CONTRACT_SOURCE,
            expected_root
            / "nixos/production/critical-user-home-data-contract-v1.json",
        )
        self.assertEqual(
            helper.RECOVERY_CONTRACT_SOURCE,
            expected_root / "nixos/production/recovery-contract-v1.json",
        )
        self.assertEqual(
            helper.STATE_ROOT,
            Path("/run/grabowski/critical-user-data-inventory"),
        )
        for digest in (
            helper.AUTHORIZED_SCANNER_SHA256,
            helper.AUTHORIZED_AGGREGATE_SCANNER_SHA256,
            helper.AUTHORIZED_CONTRACT_SHA256,
            helper.AUTHORIZED_HOME_CONTRACT_SHA256,
            helper.AUTHORIZED_RECOVERY_CONTRACT_SHA256,
        ):
            self.assertRegex(digest, r"[0-9a-f]{64}\Z")

    def test_request_digest_pair_is_authority_not_caller_choice(self) -> None:
        first = (helper.SNAPSHOT_ROOT, helper.UNIT)
        self.assertIn(helper.AUTHORIZED_SCANNER_SHA256, str(first[0]))
        self.assertIn(helper.AUTHORIZED_CONTRACT_SHA256, str(first[0]))
        for scanner, contract in (
            ("0" * 64, helper.AUTHORIZED_CONTRACT_SHA256),
            (helper.AUTHORIZED_SCANNER_SHA256, "0" * 64),
        ):
            with self.subTest(scanner=scanner, contract=contract):
                with self.assertRaisesRegex(
                    helper.InventoryHelperError, "not authorized"
                ):
                    helper._apply_binding(scanner, contract)

    def test_current_aggregate_contract_identity_is_required(self) -> None:
        contract = _aggregate_contract(
            helper.AUTHORIZED_SCANNER_SHA256,
            helper.AUTHORIZED_AGGREGATE_SCANNER_SHA256,
            helper.AUTHORIZED_HOME_CONTRACT_SHA256,
        )
        helper._validate_contract(_canonical(contract))
        wrong_execution = dict(contract)
        wrong_implementation = dict(contract["inventory_implementation"])
        wrong_implementation["aggregate_execution_mode"] = "unverified-direct-exec"
        wrong_execution["inventory_implementation"] = wrong_implementation
        with self.assertRaises(helper.InventoryHelperError):
            helper._validate_contract(_canonical(wrong_execution))
        for mutation in (
            {"scope_semantics": "explicit-root-set-default-include"},
            {
                "members": [
                    *contract["members"],
                    {
                        "id": "docker-volumes",
                        "contract_file": "critical-docker-volume-data-contract-v1.json",
                        "contract_sha256": "d" * 64,
                        "destination": {},
                        "restore_mode": "staged",
                    },
                ]
            },
        ):
            changed = dict(contract)
            changed.update(mutation)
            with self.subTest(mutation=mutation):
                with self.assertRaises(helper.InventoryHelperError):
                    helper._validate_contract(_canonical(changed))

    def test_aggregate_argv_uses_internal_external_verified_executor(self) -> None:
        argv = helper.aggregate_argv()
        self.assertEqual(argv[0], str(helper.HELPER))
        self.assertEqual(len(argv), 2)
        request = json.loads(argv[1])
        self.assertEqual(request["operation"], "aggregate")
        self.assertEqual(
            request["scanner_sha256"], helper.AUTHORIZED_SCANNER_SHA256
        )
        self.assertEqual(
            request["contract_sha256"], helper.AUTHORIZED_CONTRACT_SHA256
        )
        self.assertEqual(
            helper.AGGREGATE_EXECUTION_MODE,
            "external-verified-payload-exec-v1",
        )
        self.assertNotIn("--verified-payload-bootstrap", argv)

    def test_external_verified_payload_executor_sets_authoritative_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aggregate_path = root / "nixos_critical_data_inventory.py"
            contract_path = root / "critical-user-data-contract-v1.json"
            aggregate_payload = b"""AGGREGATE_EXECUTION_MODE = "external-verified-payload-exec-v1"
_VERIFIED_EXECUTION = False
def collect_inventory(contract_path, *, classification_only=False, max_exclusion_samples=0, _contract_snapshot=None, _aggregate_script_bytes=None):
    return {"verified": _VERIFIED_EXECUTION, "classification_only": classification_only}
"""
            contract_payload = b'{"schema_version":1}\n'
            aggregate_path.write_bytes(aggregate_payload)
            contract_path.write_bytes(contract_payload)
            aggregate_path.chmod(0o500)
            contract_path.chmod(0o400)

            def read_snapshot(path: Path, **_kwargs: object) -> bytes:
                return path.read_bytes()

            with (
                mock.patch.object(helper, "AGGREGATE_SCANNER_SNAPSHOT", aggregate_path),
                mock.patch.object(helper, "CONTRACT_SNAPSHOT", contract_path),
                mock.patch.object(
                    helper,
                    "AUTHORIZED_AGGREGATE_SCANNER_SHA256",
                    _sha(aggregate_payload),
                ),
                mock.patch.object(
                    helper, "AUTHORIZED_CONTRACT_SHA256", _sha(contract_payload)
                ),
                mock.patch.object(
                    helper, "_read_stable_regular", side_effect=read_snapshot
                ),
            ):
                value = helper._verified_aggregate_inventory()

        self.assertTrue(value["verified"])
        self.assertFalse(value["classification_only"])

    def test_lock_creates_digest_binding_directory_before_open(self) -> None:
        events: list[tuple[str, object]] = []

        def ensure(path: Path) -> None:
            events.append(("ensure", path))

        def open_lock(path: Path, *_args: object) -> int:
            events.append(("open", path))
            return 19

        info = mock.Mock(
            st_mode=helper.stat.S_IFREG | 0o600,
            st_uid=0,
            st_nlink=1,
        )
        with (
            mock.patch.object(helper, "_ensure_private_directory", side_effect=ensure),
            mock.patch.object(helper.os, "open", side_effect=open_lock),
            mock.patch.object(helper.os, "fstat", return_value=info),
            mock.patch.object(helper.fcntl, "flock") as flock,
        ):
            descriptor = helper._lock()

        self.assertEqual(descriptor, 19)
        self.assertEqual(
            events[:3],
            [
                ("ensure", helper.STATE_ROOT),
                ("ensure", helper.SNAPSHOT_ROOT),
                ("open", helper.LOCK_PATH),
            ],
        )
        flock.assert_called_once_with(19, helper.fcntl.LOCK_EX)

    def test_systemd_sandbox_is_read_only_except_inventory_state(self) -> None:
        argv = helper.systemd_start_argv()
        required = {
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=read-only",
            "--property=PrivateTmp=yes",
            "--property=PrivateNetwork=yes",
            "--property=PrivateDevices=yes",
            "--property=NoNewPrivileges=yes",
            "--property=UMask=0077",
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectKernelLogs=yes",
            "--property=ProtectControlGroups=yes",
            "--property=ProtectHostname=yes",
            "--property=ProtectClock=yes",
            "--property=RestrictSUIDSGID=yes",
            "--property=RestrictRealtime=yes",
            "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH",
            f"--property=ReadWritePaths={helper.STATE_ROOT}",
        }
        self.assertTrue(required.issubset(set(argv)))
        self.assertFalse(any("ReadWritePaths=/home" in token for token in argv))
        self.assertFalse(any("/var/lib/docker" in token for token in argv))
        self.assertEqual(argv[-2], str(helper.HELPER))
        request = json.loads(argv[-1])
        self.assertEqual(request["operation"], "execute")
        self.assertEqual(
            request["scanner_sha256"], helper.AUTHORIZED_SCANNER_SHA256
        )
        self.assertEqual(
            request["contract_sha256"], helper.AUTHORIZED_CONTRACT_SHA256
        )

    def test_start_accepts_fast_terminal_unit_with_sealed_result(self) -> None:
        passed = self._passed_result()
        inactive = {
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "SubState": "dead",
            "Result": "success",
        }
        with (
            mock.patch.object(helper, "_lock", return_value=19),
            mock.patch.object(helper, "_snapshot_sources"),
            mock.patch.object(helper, "_unit_state", side_effect=[inactive, inactive]),
            mock.patch.object(helper, "_read_result", side_effect=[None, passed]) as read_result,
            mock.patch.object(
                helper.subprocess, "run", return_value=mock.Mock(returncode=0)
            ) as run,
            mock.patch.object(helper.os, "close"),
        ):
            result = helper._start()

        self.assertEqual(result, passed)
        self.assertEqual(read_result.call_count, 2)
        run.assert_called_once()

    def _fixture(self) -> tuple[tempfile.TemporaryDirectory[str], dict[str, object]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        source = root / "source"
        source.mkdir()
        scanner = b"print('root scanner fixture')\n"
        aggregate_scanner = b"print('aggregate scanner fixture')\n"
        home_contract = _canonical(_home_contract())
        scanner_path = source / "nixos_critical_user_data_inventory.py"
        aggregate_path = source / "nixos_critical_data_inventory.py"
        home_path = source / "critical-user-home-data-contract-v1.json"
        scanner_path.write_bytes(scanner)
        aggregate_path.write_bytes(aggregate_scanner)
        home_path.write_bytes(home_contract)
        scanner_sha = _sha(scanner)
        aggregate_sha = _sha(aggregate_scanner)
        home_sha = _sha(home_contract)
        contract = _canonical(
            _aggregate_contract(scanner_sha, aggregate_sha, home_sha)
        )
        contract_path = source / "critical-user-data-contract-v1.json"
        contract_path.write_bytes(contract)
        recovery_contract = _canonical(_recovery_contract(_sha(contract)))
        recovery_path = source / "recovery-contract-v1.json"
        recovery_path.write_bytes(recovery_contract)
        state = root / "state"
        state.mkdir(mode=0o700)
        return temporary, {
            "scanner": scanner,
            "aggregate_scanner": aggregate_scanner,
            "contract": contract,
            "home_contract": home_contract,
            "recovery_contract": recovery_contract,
            "scanner_path": scanner_path,
            "aggregate_path": aggregate_path,
            "contract_path": contract_path,
            "home_path": home_path,
            "recovery_path": recovery_path,
            "scanner_sha": scanner_sha,
            "aggregate_sha": aggregate_sha,
            "contract_sha": _sha(contract),
            "home_sha": home_sha,
            "recovery_sha": _sha(recovery_contract),
            "state": state,
        }

    def _snapshot_context(self, fx: dict[str, object]) -> ExitStack:
        stack = ExitStack()
        for name, value in (
            ("SCANNER_SOURCE", fx["scanner_path"]),
            ("AGGREGATE_SCANNER_SOURCE", fx["aggregate_path"]),
            ("CONTRACT_SOURCE", fx["contract_path"]),
            ("HOME_CONTRACT_SOURCE", fx["home_path"]),
            ("RECOVERY_CONTRACT_SOURCE", fx["recovery_path"]),
            ("AUTHORIZED_SCANNER_SHA256", fx["scanner_sha"]),
            ("AUTHORIZED_AGGREGATE_SCANNER_SHA256", fx["aggregate_sha"]),
            ("AUTHORIZED_CONTRACT_SHA256", fx["contract_sha"]),
            ("AUTHORIZED_HOME_CONTRACT_SHA256", fx["home_sha"]),
            ("AUTHORIZED_RECOVERY_CONTRACT_SHA256", fx["recovery_sha"]),
            ("STATE_ROOT", fx["state"]),
        ):
            stack.enter_context(mock.patch.object(helper, name, value))
        helper._apply_binding(
            str(fx["scanner_sha"]),
            str(fx["contract_sha"]),
        )
        return stack

    def test_snapshot_rejects_changed_source_after_authority_binding(self) -> None:
        temporary, fx = self._fixture()
        self.addCleanup(temporary.cleanup)
        with self._snapshot_context(fx):
            scanner_path = fx["scanner_path"]
            assert isinstance(scanner_path, Path)
            scanner_path.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(
                helper.InventoryHelperError, "scanner digest"
            ):
                helper._snapshot_sources()

    def test_snapshot_rejects_aggregate_or_home_contract_drift(self) -> None:
        for key, message in (
            ("aggregate_path", "aggregate inventory scanner digest"),
            ("home_path", "home contract digest"),
            ("recovery_path", "recovery contract digest"),
        ):
            temporary, fx = self._fixture()
            self.addCleanup(temporary.cleanup)
            with self.subTest(key=key), self._snapshot_context(fx):
                path = fx[key]
                assert isinstance(path, Path)
                path.write_text("{}\n", encoding="utf-8")
                with self.assertRaisesRegex(helper.InventoryHelperError, message):
                    helper._snapshot_sources()

    def test_snapshot_materializes_only_verified_root_owned_sources(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned snapshot metadata test requires root")
        temporary, fx = self._fixture()
        self.addCleanup(temporary.cleanup)
        with self._snapshot_context(fx):
            helper._snapshot_sources()
            expected = {
                helper.SCANNER_SNAPSHOT: (fx["scanner"], 0o500),
                helper.AGGREGATE_SCANNER_SNAPSHOT: (
                    fx["aggregate_scanner"],
                    0o500,
                ),
                helper.CONTRACT_SNAPSHOT: (fx["contract"], 0o400),
                helper.HOME_CONTRACT_SNAPSHOT: (fx["home_contract"], 0o400),
                helper.RECOVERY_CONTRACT_SNAPSHOT: (fx["recovery_contract"], 0o400),
            }
            for path, (payload, mode) in expected.items():
                self.assertEqual(path.read_bytes(), payload)
                self.assertEqual(path.stat().st_mode & 0o777, mode)
                self.assertEqual(path.stat().st_uid, 0)

    def test_inventory_output_is_single_home_member_and_digest_bound(self) -> None:
        value = _aggregate_inventory(
            contract_sha256=helper.AUTHORIZED_CONTRACT_SHA256,
            home_contract_sha256=helper.AUTHORIZED_HOME_CONTRACT_SHA256,
        )
        normalized = helper._validate_inventory_output(_canonical(value))
        self.assertEqual(normalized, value)
        for mutation in (
            {"member_count": 2},
            {"scope_semantics": "explicit-root-set-default-include"},
            {"members": [*value["members"], dict(value["members"][0])]},
            {"inventory_sha256": "f" * 64},
            {"private_path": "/home/alex/private"},
        ):
            changed = dict(value)
            changed.update(mutation)
            with self.subTest(mutation=mutation):
                with self.assertRaises(helper.InventoryHelperError):
                    helper._validate_inventory_output(_canonical(changed))

    def test_helper_request_rejects_paths_modes_and_unauthorized_digests(self) -> None:
        with mock.patch.object(helper.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(helper.InventoryHelperError, "operation"):
                helper.main([_target("start"), "/tmp/other-scanner.py"])
            for extra in (
                {"scanner_path": "/tmp/inventory.py"},
                {"contract_path": "/tmp/contract.json"},
                {"classification_only": True},
                {"max_exclusion_samples": 1},
                {"argv": ["/bin/sh"]},
                {"shell": "/bin/sh"},
            ):
                request = json.loads(_target("start"))
                request.update(extra)
                with self.subTest(extra=extra):
                    with self.assertRaisesRegex(
                        helper.InventoryHelperError, "request"
                    ):
                        helper.main(
                            [
                                json.dumps(
                                    request,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                )
                            ]
                        )
            with self.assertRaisesRegex(
                helper.InventoryHelperError, "not authorized"
            ):
                helper.main(
                    [
                        _target(
                            "start",
                            scanner_sha256="0" * 64,
                            contract_sha256=helper.AUTHORIZED_CONTRACT_SHA256,
                        )
                    ]
                )

    def _passed_result(self) -> dict[str, object]:
        inventory = _aggregate_inventory(
            contract_sha256=helper.AUTHORIZED_CONTRACT_SHA256,
            home_contract_sha256=helper.AUTHORIZED_HOME_CONTRACT_SHA256,
        )
        return helper._seal_result(
            helper._unsigned_result(status="passed", inventory=inventory)
        )

    def test_public_projection_returns_only_safe_aggregate_fields(self) -> None:
        result = self._passed_result()
        projected = privileged._critical_inventory_projection(
            result,
            scanner_sha256=helper.AUTHORIZED_SCANNER_SHA256,
            contract_sha256=helper.AUTHORIZED_CONTRACT_SHA256,
        )
        self.assertEqual(
            set(projected),
            {
                "schema_version",
                "kind",
                "status",
                "scanner_sha256",
                "contract_sha256",
                "completed_at_unix",
                "result_sha256",
                "inventory_sha256",
                "record_count",
                "regular_file_bytes",
                "exclusion_boundary_count",
            },
        )
        for forbidden in (
            "inventory",
            "members",
            "root",
            "path",
            "content",
        ):
            self.assertNotIn(forbidden, projected)

    def test_public_projection_rejects_private_payload_and_digest_drift(self) -> None:
        result = self._passed_result()
        leaked = dict(result)
        leaked["private_path"] = "/home/alex/private"
        with self.assertRaises(RuntimeError):
            privileged._critical_inventory_projection(
                leaked,
                scanner_sha256=helper.AUTHORIZED_SCANNER_SHA256,
                contract_sha256=helper.AUTHORIZED_CONTRACT_SHA256,
            )
        drifted = dict(result)
        drifted["scanner_sha256"] = "f" * 64
        with self.assertRaisesRegex(RuntimeError, "scanner binding drifted"):
            privileged._critical_inventory_projection(
                drifted,
                scanner_sha256=helper.AUTHORIZED_SCANNER_SHA256,
                contract_sha256=helper.AUTHORIZED_CONTRACT_SHA256,
            )
        bad_inventory = dict(result)
        bad_inventory["inventory"] = dict(result["inventory"])
        bad_inventory["inventory"]["members"] = [
            {
                **bad_inventory["inventory"]["members"][0],
                "path": "/home/alex/private",
            }
        ]
        with self.assertRaises(RuntimeError):
            privileged._critical_inventory_projection(
                bad_inventory,
                scanner_sha256=helper.AUTHORIZED_SCANNER_SHA256,
                contract_sha256=helper.AUTHORIZED_CONTRACT_SHA256,
            )

    def test_public_tool_does_not_return_raw_broker_audit_or_inner_payload(self) -> None:
        result = self._passed_result()
        outer = {
            "returncode": 0,
            "timed_out": False,
            "stdout": json.dumps(result, sort_keys=True, separators=(",", ":")),
            "audit": {"private_path": "/home/alex/private"},
        }
        invoked = {
            "request_id": "req-safe",
            "reference_sha256": "9" * 64,
            "broker_client_timed_out": False,
            "broker_response": outer,
        }
        with (
            mock.patch.object(
                privileged.operator,
                "_require_operator_mutation",
                return_value=None,
            ),
            mock.patch.object(
                privileged,
                "_invoke_privileged_reference",
                return_value=invoked,
            ),
        ):
            value = privileged.grabowski_critical_user_data_inventory(
                "result",
                helper.AUTHORIZED_SCANNER_SHA256,
                helper.AUTHORIZED_CONTRACT_SHA256,
            )
        self.assertNotIn("audit", value)
        self.assertNotIn("broker_response", value)
        self.assertNotIn("stdout", value)
        self.assertNotIn("inventory", value["result"])
        self.assertEqual(value["request_id"], "req-safe")
        self.assertEqual(value["reference_sha256"], "9" * 64)



if __name__ == "__main__":
    unittest.main()
