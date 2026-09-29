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
    scanner_sha256: str = "a" * 64,
    contract_sha256: str = "b" * 64,
) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": operation,
            "scanner_sha256": scanner_sha256,
            "contract_sha256": contract_sha256,
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


def _member_contract(member_id: str) -> dict[str, object]:
    definition = helper.MEMBER_IDENTITIES[member_id]
    value: dict[str, object] = {
        "schema_version": 1,
        "kind": helper.SCOPE_KIND,
        "scope": definition["scope"],
        "scope_semantics": definition["scope_semantics"],
        "root": definition["root"],
        "logical_root": definition["root"],
        "inventory": {
            "schema": helper.MEMBER_INVENTORY_KIND,
            "algorithm": helper.MEMBER_INVENTORY_ALGORITHM,
            "same_filesystem_only": True,
            "follow_symlinks": False,
            "regular_file_content_sha256": True,
            "directory_mode_bound": True,
            "regular_file_mode_bound": True,
            "symlink_target_bound": True,
            "special_files": "excluded-runtime-only",
            "unreadable_included_path": "fail",
            "changed_during_hash": "fail",
        },
        "exclusions": {
            "top_level_prefixes": [],
            "roots": [],
            "file_name_prefixes_under": [],
            "file_name_prefix_suffixes_under": [],
            "directory_names_under": [],
        },
    }
    if member_id == "docker-volumes":
        value["source_consistency"] = {
            "full_authoritative_inventory_requires_docker_quiesced": True
        }
    return value


def _aggregate_contract(
    scanner_sha256: str,
    member_digests: dict[str, str],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": helper.SCOPE_KIND,
        "scope": "critical-user-data",
        "scope_semantics": helper.SCOPE_SEMANTICS,
        "members": [
            {
                "id": member_id,
                "contract_file": helper.MEMBER_IDENTITIES[member_id]["snapshot_name"],
                "contract_sha256": member_digests[member_id],
                "destination": helper.MEMBER_IDENTITIES[member_id]["destination"],
                "restore_mode": helper.MEMBER_IDENTITIES[member_id]["restore_mode"],
            }
            for member_id in ("home", "docker-volumes")
        ],
        "inventory_implementation": {
            "algorithm": helper.INVENTORY_ALGORITHM,
            "root_inventory_script": "scripts/nixos_critical_user_data_inventory.py",
            "root_inventory_script_sha256": scanner_sha256,
            "aggregate_inventory_script": "scripts/nixos_critical_data_inventory.py",
            "aggregate_inventory_script_sha256": "e" * 64,
            "member_contract_digest_bound": True,
            "source_and_restored_aggregate_inventory_sha256_must_match": True,
        },
    }


def _member_inventory(
    member_id: str,
    *,
    contract_sha256: str,
    inventory_sha256: str,
    exclusion_sha256: str,
) -> dict[str, object]:
    definition = helper.MEMBER_IDENTITIES[member_id]
    member_sha = contract_sha256
    return {
        "schema_version": 1,
        "kind": helper.MEMBER_INVENTORY_KIND,
        "scope": definition["scope"],
        "root": definition["root"],
        "algorithm": helper.MEMBER_INVENTORY_ALGORITHM,
        "critical_scope_sha256": member_sha,
        "contract_sha256": member_sha,
        "authoritative_inventory": True,
        "inventory_sha256": inventory_sha256,
        "record_count": 6,
        "type_counts": {"directory": 1, "regular": 4, "symlink": 1},
        "regular_file_bytes": 1234,
        "exclusion_boundary_count": 2,
        "exclusion_boundary_sha256": exclusion_sha256,
        "exclusion_class_counts": {
            "cache": 1,
            "transient-runtime-special": 1,
        },
        "exclusion_samples": [],
        "production_effects_authorized": False,
    }


class CriticalUserDataInventoryPrivilegedTests(unittest.TestCase):
    MEMBER_DIGESTS = {
        "docker-volumes": "c" * 64,
        "home": "d" * 64,
    }

    def setUp(self) -> None:
        helper._apply_binding("a" * 64, "b" * 64)

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

    def test_source_paths_are_fixed_to_canonical_migration_worktree(self) -> None:
        self.assertEqual(
            helper.SCANNER_SOURCE,
            Path(
                "/home/alex/repos/.grabowski-worktrees/"
                "heim-pc-critical-user-data-scope-20260928/"
                "scripts/nixos_critical_user_data_inventory.py"
            ),
        )
        self.assertEqual(
            helper.CONTRACT_SOURCE,
            Path(
                "/home/alex/repos/.grabowski-worktrees/"
                "heim-pc-critical-user-data-scope-20260928/"
                "nixos/production/critical-user-data-contract-v1.json"
            ),
        )

    def test_state_and_unit_are_bound_to_full_request_digest_pair(self) -> None:
        helper._apply_binding("1" * 64, "2" * 64)
        first = (helper.SNAPSHOT_ROOT, helper.UNIT)
        helper._apply_binding("3" * 64, "4" * 64)
        second = (helper.SNAPSHOT_ROOT, helper.UNIT)
        self.assertNotEqual(first, second)
        self.assertIn("1" * 64, str(first[0]))
        self.assertIn("2" * 64, str(first[0]))
        self.assertIn("1" * 64, first[1])
        self.assertIn("2" * 64, first[1])

    def test_current_aggregate_contract_identity_is_required(self) -> None:
        scanner = b"print('safe')\n"
        member_payloads = {
            member_id: _canonical(_member_contract(member_id))
            for member_id in helper.MEMBER_IDENTITIES
        }
        digests = {
            member_id: _sha(payload)
            for member_id, payload in member_payloads.items()
        }
        helper._apply_binding(_sha(scanner), "b" * 64)
        aggregate = _aggregate_contract(_sha(scanner), digests)
        bindings = helper._validate_contract(_canonical(aggregate))
        self.assertEqual(set(bindings), set(helper.MEMBER_IDENTITIES))
        historical = dict(aggregate)
        historical["scope_semantics"] = "whole-home-by-default"
        historical["root"] = "/home/alex"
        historical["logical_root"] = "/home/alex"
        with self.assertRaisesRegex(helper.InventoryHelperError, "identity"):
            helper._validate_contract(_canonical(historical))

    def test_scanner_argv_is_authoritative_zero_sample_and_member_pinned(self) -> None:
        helper._apply_binding("a" * 64, "b" * 64)
        for member_id, member_sha in self.MEMBER_DIGESTS.items():
            with self.subTest(member_id=member_id):
                argv = helper.scanner_argv(member_id, member_sha)
                self.assertEqual(
                    argv[0:3],
                    ["/usr/bin/python3", "-B", str(helper.SCANNER_SNAPSHOT)],
                )
                self.assertNotIn("--classification-only", argv)
                self.assertEqual(argv[argv.index("--max-exclusion-samples") + 1], "0")
                self.assertEqual(
                    argv[argv.index("--expected-script-sha256") + 1],
                    "a" * 64,
                )
                self.assertEqual(
                    argv[argv.index("--expected-contract-sha256") + 1],
                    member_sha,
                )
                self.assertEqual(
                    argv[argv.index("--contract") + 1],
                    str(helper._member_snapshot(member_id)),
                )

    def test_lock_creates_digest_binding_directory_before_open(self) -> None:
        helper._apply_binding("a" * 64, "b" * 64)
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
        helper._apply_binding("a" * 64, "b" * 64)
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
        self.assertFalse(any("/var/lib/docker" in token and "ReadWrite" in token for token in argv))
        self.assertFalse(any("/dev/disk/" in token for token in argv))
        self.assertEqual(argv[-2], str(helper.HELPER))
        request = json.loads(argv[-1])
        self.assertEqual(request["operation"], "execute")
        self.assertEqual(request["scanner_sha256"], "a" * 64)
        self.assertEqual(request["contract_sha256"], "b" * 64)

    def _fixture(
        self,
        *,
        scanner: bytes = b"print('safe')\n",
    ) -> tuple[tempfile.TemporaryDirectory[str], dict[str, object]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        source = root / "source"
        source.mkdir()
        scanner_path = source / "inventory.py"
        scanner_path.write_bytes(scanner)
        member_payloads: dict[str, bytes] = {}
        member_digests: dict[str, str] = {}
        member_paths: dict[str, Path] = {}
        for member_id, definition in helper.MEMBER_IDENTITIES.items():
            payload = _canonical(_member_contract(member_id))
            path = source / definition["snapshot_name"]
            path.write_bytes(payload)
            member_payloads[member_id] = payload
            member_digests[member_id] = _sha(payload)
            member_paths[member_id] = path
        aggregate = _aggregate_contract(_sha(scanner), member_digests)
        contract_payload = _canonical(aggregate)
        contract_path = source / "critical-user-data-contract-v1.json"
        contract_path.write_bytes(contract_payload)
        state = root / "state"
        state.mkdir(mode=0o700)
        return temporary, {
            "scanner_path": scanner_path,
            "contract_path": contract_path,
            "scanner": scanner,
            "contract": contract_payload,
            "member_payloads": member_payloads,
            "member_paths": member_paths,
            "member_digests": member_digests,
            "state": state,
        }

    def _snapshot_context(
        self,
        fx: dict[str, object],
        *,
        scanner_sha256: str | None = None,
        contract_sha256: str | None = None,
    ) -> ExitStack:
        scanner = fx["scanner"]
        contract = fx["contract"]
        state = fx["state"]
        assert isinstance(scanner, bytes)
        assert isinstance(contract, bytes)
        assert isinstance(state, Path)
        stack = ExitStack()
        stack.enter_context(mock.patch.object(helper, "SCANNER_SOURCE", fx["scanner_path"]))
        stack.enter_context(mock.patch.object(helper, "CONTRACT_SOURCE", fx["contract_path"]))
        identities = {
            member_id: dict(identity)
            for member_id, identity in helper.MEMBER_IDENTITIES.items()
        }
        member_paths = fx["member_paths"]
        assert isinstance(member_paths, dict)
        for member_id in identities:
            identities[member_id]["source"] = member_paths[member_id]
        stack.enter_context(mock.patch.object(helper, "MEMBER_IDENTITIES", identities))
        stack.enter_context(mock.patch.object(helper, "STATE_ROOT", state))
        helper._apply_binding(
            scanner_sha256 or _sha(scanner),
            contract_sha256 or _sha(contract),
        )
        return stack

    def test_snapshot_rejects_wrong_scanner_digest(self) -> None:
        temporary, fx = self._fixture()
        self.addCleanup(temporary.cleanup)
        with self._snapshot_context(fx, scanner_sha256="0" * 64):
            with self.assertRaisesRegex(helper.InventoryHelperError, "scanner digest"):
                helper._snapshot_sources()

    def test_snapshot_rejects_wrong_aggregate_contract_digest(self) -> None:
        temporary, fx = self._fixture()
        self.addCleanup(temporary.cleanup)
        with self._snapshot_context(fx, contract_sha256="0" * 64):
            with self.assertRaisesRegex(helper.InventoryHelperError, "contract digest"):
                helper._snapshot_sources()

    def test_snapshot_rejects_member_contract_digest_drift(self) -> None:
        temporary, fx = self._fixture()
        self.addCleanup(temporary.cleanup)
        member_paths = fx["member_paths"]
        assert isinstance(member_paths, dict)
        member_paths["home"].write_text("{}\n", encoding="utf-8")
        with self._snapshot_context(fx):
            with self.assertRaisesRegex(helper.InventoryHelperError, "member contract digest"):
                helper._snapshot_sources()

    def test_snapshot_materializes_only_verified_root_owned_sources(self) -> None:
        if os.geteuid() != 0:
            self.skipTest("root-owned snapshot metadata test requires root")
        temporary, fx = self._fixture()
        self.addCleanup(temporary.cleanup)
        with self._snapshot_context(fx):
            helper._snapshot_sources()
            self.assertEqual(helper.SCANNER_SNAPSHOT.read_bytes(), fx["scanner"])
            self.assertEqual(helper.CONTRACT_SNAPSHOT.read_bytes(), fx["contract"])
            self.assertEqual(helper.SCANNER_SNAPSHOT.stat().st_mode & 0o777, 0o500)
            self.assertEqual(helper.CONTRACT_SNAPSHOT.stat().st_mode & 0o777, 0o400)
            for member_id, expected in fx["member_payloads"].items():
                self.assertEqual(
                    helper._member_snapshot(member_id).read_bytes(),
                    expected,
                )
                self.assertEqual(
                    helper._member_snapshot(member_id).stat().st_mode & 0o777,
                    0o400,
                )

    def test_member_inventory_rejects_classification_samples_and_private_fields(self) -> None:
        value = _member_inventory(
            "home",
            contract_sha256=self.MEMBER_DIGESTS["home"],
            inventory_sha256="1" * 64,
            exclusion_sha256="2" * 64,
        )
        normalized = helper._validate_member_inventory_output(
            _canonical(value),
            member_id="home",
            contract_sha256=self.MEMBER_DIGESTS["home"],
        )
        self.assertEqual(normalized, value)
        for mutation in (
            {"authoritative_inventory": False, "inventory_sha256": None},
            {"production_effects_authorized": True},
            {"exclusion_samples": [{"path": "/home/alex/private"}]},
            {"path": "/home/alex/private"},
        ):
            changed = dict(value)
            changed.update(mutation)
            with self.subTest(mutation=mutation):
                with self.assertRaises(helper.InventoryHelperError):
                    helper._validate_member_inventory_output(
                        _canonical(changed),
                        member_id="home",
                        contract_sha256=self.MEMBER_DIGESTS["home"],
                    )

    def test_aggregate_matches_member_inventory_digest_contract(self) -> None:
        helper._apply_binding("a" * 64, "b" * 64)
        members = {
            "docker-volumes": _member_inventory(
                "docker-volumes",
                contract_sha256=self.MEMBER_DIGESTS["docker-volumes"],
                inventory_sha256="1" * 64,
                exclusion_sha256="2" * 64,
            ),
            "home": _member_inventory(
                "home",
                contract_sha256=self.MEMBER_DIGESTS["home"],
                inventory_sha256="3" * 64,
                exclusion_sha256="4" * 64,
            ),
        }
        aggregate = helper._aggregate_member_inventories(
            members,
            self.MEMBER_DIGESTS,
        )
        expected = hashlib.sha256()
        for member_id in sorted(members):
            expected.update(
                _canonical(
                    {
                        "id": member_id,
                        "contract_sha256": self.MEMBER_DIGESTS[member_id],
                        "inventory_sha256": members[member_id]["inventory_sha256"],
                    }
                )
            )
        self.assertEqual(aggregate["inventory_sha256"], expected.hexdigest())
        self.assertTrue(aggregate["authoritative_inventory"])
        self.assertFalse(aggregate["production_effects_authorized"])
        self.assertEqual(aggregate["exclusion_samples"], [])
        self.assertEqual(aggregate["record_count"], 12)
        self.assertEqual(aggregate["type_counts"], {
            "directory": 2,
            "regular": 8,
            "symlink": 2,
        })

    def test_helper_request_rejects_paths_modes_and_extra_arguments(self) -> None:
        helper._apply_binding("a" * 64, "b" * 64)
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

    def _passed_result(self) -> dict[str, object]:
        helper._apply_binding("a" * 64, "b" * 64)
        inventory = helper._aggregate_member_inventories(
            {
                "docker-volumes": _member_inventory(
                    "docker-volumes",
                    contract_sha256=self.MEMBER_DIGESTS["docker-volumes"],
                    inventory_sha256="1" * 64,
                    exclusion_sha256="2" * 64,
                ),
                "home": _member_inventory(
                    "home",
                    contract_sha256=self.MEMBER_DIGESTS["home"],
                    inventory_sha256="3" * 64,
                    exclusion_sha256="4" * 64,
                ),
            },
            self.MEMBER_DIGESTS,
        )
        return helper._seal_result(
            helper._unsigned_result(status="passed", inventory=inventory)
        )

    def test_public_projection_returns_only_safe_aggregate_fields(self) -> None:
        result = self._passed_result()
        projected = privileged._critical_inventory_projection(
            result,
            scanner_sha256="a" * 64,
            contract_sha256="b" * 64,
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
                "type_counts",
                "regular_file_bytes",
                "exclusion_boundary_count",
                "exclusion_boundary_sha256",
                "exclusion_class_counts",
            },
        )
        for forbidden in ("inventory", "members", "root", "exclusion_samples", "path"):
            self.assertNotIn(forbidden, projected)

    def test_public_projection_rejects_private_top_level_payload_and_digest_drift(self) -> None:
        result = self._passed_result()
        leaked = dict(result)
        leaked["private_path"] = "/home/alex/private"
        with self.assertRaises(RuntimeError):
            privileged._critical_inventory_projection(
                leaked,
                scanner_sha256="a" * 64,
                contract_sha256="b" * 64,
            )
        drifted = dict(result)
        drifted["scanner_sha256"] = "f" * 64
        with self.assertRaisesRegex(RuntimeError, "scanner binding drifted"):
            privileged._critical_inventory_projection(
                drifted,
                scanner_sha256="a" * 64,
                contract_sha256="b" * 64,
            )
        drifted = dict(result)
        drifted["contract_sha256"] = "f" * 64
        with self.assertRaisesRegex(RuntimeError, "contract binding drifted"):
            privileged._critical_inventory_projection(
                drifted,
                scanner_sha256="a" * 64,
                contract_sha256="b" * 64,
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
                "a" * 64,
                "b" * 64,
            )
        self.assertNotIn("audit", value)
        self.assertNotIn("broker_response", value)
        self.assertNotIn("stdout", value)
        self.assertNotIn("inventory", value["result"])
        self.assertEqual(value["request_id"], "req-safe")
        self.assertEqual(value["reference_sha256"], "9" * 64)

    def test_docker_quiescence_is_fail_closed(self) -> None:
        completed = mock.Mock(returncode=0, stdout=b"container-id\n", stderr=b"")
        with tempfile.TemporaryDirectory() as temporary:
            docker = Path(temporary) / "docker"
            docker.write_text("", encoding="utf-8")
            with (
                mock.patch.object(helper, "DOCKER", docker),
                mock.patch.object(helper.subprocess, "run", return_value=completed),
            ):
                with self.assertRaisesRegex(
                    helper.InventoryHelperError,
                    "requires all containers stopped",
                ):
                    helper._docker_quiesced()


if __name__ == "__main__":
    unittest.main()
