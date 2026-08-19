from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_fleet as fleet
import grabowski_fleet_mutation as mutation
import grabowski_operations as operations


def _write_registry(path: Path, hosts: dict[str, dict[str, object]]) -> bytes:
    payload = (
        json.dumps(
            {"schema_version": 1, "hosts": hosts},
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    path.write_bytes(payload)
    return payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _host(
    *,
    target: str = "mohr-@deepthought-42",
    enabled: bool = True,
    roles: list[str] | None = None,
) -> dict[str, object]:
    return {
        "transport": "ssh",
        "target": target,
        "enabled": enabled,
        "roles": roles or ["windows", "workstation", "joerg"],
        "command_allowlist": ["*"],
        "connect_timeout_seconds": 10,
        "remote_command_mode": "windows-powershell",
    }


def _request(
    operation: str,
    host: str,
    expected: str,
    host_spec: dict[str, object] | None = None,
) -> dict[str, object]:
    request: dict[str, object] = {
        "schema_version": 1,
        "operation": operation,
        "host": host,
        "expected_registry_sha256": expected,
    }
    if host_spec is not None:
        request["host_spec"] = host_spec
    return request


class FleetRegistryMutationTests(unittest.TestCase):
    def test_add_preserves_existing_hosts_and_writes_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            original_host = {
                "transport": "local",
                "target": "local",
                "enabled": True,
                "roles": ["operator"],
                "command_allowlist": ["*"],
            }
            before = _write_registry(config, {"heim-pc": original_host})
            receipt = mutation.mutate_registry(
                _request("add", "deepthought", _sha256(before), _host()),
                path=config,
                state_root=state,
            )
            raw = json.loads(config.read_text(encoding="utf-8"))
            normalized = fleet.validate_fleet(raw)
            self.assertEqual(raw["hosts"]["heim-pc"], original_host)
            self.assertEqual(normalized["hosts"]["deepthought"], _host())
            self.assertEqual(receipt["result"], "success")
            self.assertTrue(receipt["readback"]["ok"])
            self.assertTrue(receipt["readback"]["unaffected_hosts_preserved"])
            self.assertTrue(Path(receipt["receipt_path"]).is_file())
            self.assertEqual(receipt["before_registry_sha256"], _sha256(before))
            self.assertEqual(receipt["after_registry_sha256"], _sha256(config.read_bytes()))

    def test_update_changes_only_selected_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            old = _host(roles=["windows", "workstation"])
            untouched = _host(target="other-host", roles=["windows"])
            before = _write_registry(config, {"deepthought": old, "other": untouched})
            new = _host(roles=["windows", "workstation", "joerg"])
            receipt = mutation.mutate_registry(
                _request("update", "deepthought", _sha256(before), new),
                path=config,
                state_root=state,
            )
            raw = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(fleet.validate_fleet(raw)["hosts"]["deepthought"], new)
            self.assertEqual(raw["hosts"]["other"], untouched)
            self.assertFalse(receipt["idempotent_no_change"])

    def test_disable_preserves_other_host_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            current = _host()
            before = _write_registry(config, {"deepthought": current})
            receipt = mutation.mutate_registry(
                _request("disable", "deepthought", _sha256(before)),
                path=config,
                state_root=state,
            )
            raw = json.loads(config.read_text(encoding="utf-8"))
            self.assertFalse(raw["hosts"]["deepthought"]["enabled"])
            expected = dict(current)
            expected["enabled"] = False
            self.assertEqual(raw["hosts"]["deepthought"], expected)
            self.assertFalse(receipt["readback"]["host_enabled"])

    def test_remove_deletes_only_selected_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            untouched = _host(target="other-host", roles=["windows"])
            before = _write_registry(config, {"deepthought": _host(), "other": untouched})
            receipt = mutation.mutate_registry(
                _request("remove", "deepthought", _sha256(before)),
                path=config,
                state_root=state,
            )
            raw = json.loads(config.read_text(encoding="utf-8"))
            self.assertNotIn("deepthought", raw["hosts"])
            self.assertEqual(raw["hosts"]["other"], untouched)
            self.assertFalse(receipt["readback"]["host_present"])

    def test_identical_add_is_idempotent_and_does_not_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            before = _write_registry(config, {"deepthought": _host()})
            before_stat = config.stat()
            receipt = mutation.mutate_registry(
                _request("add", "deepthought", _sha256(before), _host()),
                path=config,
                state_root=state,
            )
            self.assertEqual(config.read_bytes(), before)
            self.assertEqual(config.stat().st_ino, before_stat.st_ino)
            self.assertTrue(receipt["idempotent_no_change"])
            self.assertFalse(receipt["effect_applied"])
            self.assertEqual(receipt["before_registry_sha256"], receipt["after_registry_sha256"])

    def test_cas_conflict_refuses_to_overwrite_current_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            before = _write_registry(config, {"heim-pc": {
                "transport": "local",
                "target": "local",
                "enabled": True,
                "roles": ["operator"],
                "command_allowlist": ["*"],
            }})
            expected = _sha256(before)
            concurrent = _write_registry(config, {"heim-pc": {
                "transport": "local",
                "target": "local",
                "enabled": True,
                "roles": ["operator", "changed"],
                "command_allowlist": ["*"],
            }})
            with self.assertRaisesRegex(mutation.FleetRegistryConflict, "preimage changed"):
                mutation.mutate_registry(
                    _request("add", "deepthought", expected, _host()),
                    path=config,
                    state_root=state,
                )
            self.assertEqual(config.read_bytes(), concurrent)

    def test_invalid_ssh_target_and_incomplete_host_spec_are_rejected(self) -> None:
        complete = _host()
        incomplete = dict(complete)
        incomplete.pop("remote_command_mode")
        with self.assertRaisesRegex(ValueError, "complete v1 host contract"):
            mutation._validate_host_spec("deepthought", incomplete)
        unsafe = _host(target="-oProxyCommand=evil")
        with self.assertRaisesRegex(ValueError, "unsafe SSH target"):
            mutation._validate_host_spec("deepthought", unsafe)

    def test_failed_postflight_rolls_back_exact_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            before = _write_registry(config, {"heim-pc": {
                "transport": "local",
                "target": "local",
                "enabled": True,
                "roles": ["operator"],
                "command_allowlist": ["*"],
            }})
            with patch.object(
                mutation,
                "_assert_postflight",
                side_effect=mutation.FleetRegistryMutationError("forced postflight failure"),
            ):
                receipt = mutation.mutate_registry(
                    _request("add", "deepthought", _sha256(before), _host()),
                    path=config,
                    state_root=state,
                )
            self.assertEqual(receipt["result"], "failed")
            self.assertTrue(receipt["rollback"]["attempted"])
            self.assertTrue(receipt["rollback"]["success"])
            self.assertTrue(receipt["readback"]["ok"])
            self.assertEqual(config.read_bytes(), before)

    def test_plan_is_preimage_bound_and_does_not_expose_host_spec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            before = _write_registry(config, {})
            parameters = {
                "operation": "add",
                "host": "deepthought",
                "expected_registry_sha256": _sha256(before),
                "host_spec_json": json.dumps(_host(), sort_keys=True),
            }
            with patch.object(fleet, "FLEET_CONFIG", config):
                plan = mutation.plan_registry_mutation(parameters)
            self.assertEqual(plan["public"]["host"], "deepthought")
            self.assertEqual(plan["public"]["expected_registry_sha256"], _sha256(before))
            self.assertNotIn("host_spec", plan["public"])
            self.assertEqual(len(plan["public"]["host_spec_sha256"]), 64)

    def test_worker_launch_is_fixed_sandboxed_and_shell_free(self) -> None:
        request = _request("add", "deepthought", "a" * 64, _host())
        request["request_id"] = "f" * 32
        receipt = {
            "schema_version": 1,
            "request_id": request["request_id"],
            "request_sha256": mutation._canonical_sha256(request),
            "operation": "add",
            "host": "deepthought",
            "before_registry_sha256": "a" * 64,
            "after_registry_sha256": "b" * 64,
            "result": "success",
            "readback": {"ok": True},
        }
        fake_result = {
            "returncode": 0,
            "stdout": json.dumps(receipt) + "\n",
            "stderr": "",
            "timed_out": False,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_dir = root / "config"
            config_dir.mkdir()
            config = config_dir / "fleet.json"
            config.write_text("{}", encoding="utf-8")
            protected = config_dir / "access.json"
            protected.write_text("{}", encoding="utf-8")
            state = root / "state"
            with patch.object(fleet, "FLEET_CONFIG", config), patch.object(
                mutation, "STATE_ROOT", state
            ), patch.object(
                mutation.operator, "_run", return_value=fake_result
            ) as run:
                launch = mutation._launch_worker(request)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0:2], ["systemd-run", "--user"])
        self.assertIn("--property=ProtectHome=read-only", argv)
        self.assertIn("--property=NoNewPrivileges=yes", argv)
        self.assertIn("--property=RestrictAddressFamilies=AF_UNIX", argv)
        self.assertIn(f"--property=ReadWritePaths={config_dir}", argv)
        mutation_state_root = state / mutation.MUTATION_STATE_DIRECTORY_NAME
        self.assertIn(f"--property=ReadWritePaths={mutation_state_root}", argv)
        self.assertNotIn(f"--property=ReadWritePaths={state}", argv)
        self.assertIn(f"--property=ReadOnlyPaths={protected}", argv)
        self.assertNotIn(f"--property=ReadOnlyPaths={config}", argv)
        self.assertIn("grabowski_fleet_mutation", argv)
        self.assertNotIn("bash", argv)
        self.assertNotIn("sh", argv)
        self.assertEqual(launch["receipt"], receipt)

    def test_identical_update_is_idempotent_and_does_not_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            before = _write_registry(config, {"deepthought": _host()})
            before_stat = config.stat()
            receipt = mutation.mutate_registry(
                _request("update", "deepthought", _sha256(before), _host()),
                path=config,
                state_root=state,
            )
            self.assertEqual(config.read_bytes(), before)
            self.assertEqual(config.stat().st_ino, before_stat.st_ino)
            self.assertTrue(receipt["idempotent_no_change"])
            self.assertFalse(receipt["effect_applied"])

    def test_remove_missing_host_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            before = _write_registry(config, {"heim-pc": {
                "transport": "local",
                "target": "local",
                "enabled": True,
                "roles": ["operator"],
                "command_allowlist": ["*"],
            }})
            before_stat = config.stat()
            receipt = mutation.mutate_registry(
                _request("remove", "deepthought", _sha256(before)),
                path=config,
                state_root=state,
            )
            self.assertEqual(config.read_bytes(), before)
            self.assertEqual(config.stat().st_ino, before_stat.st_ino)
            self.assertTrue(receipt["idempotent_no_change"])
            self.assertFalse(receipt["effect_applied"])

    def test_operation_surface_routes_builtin_without_generic_argv(self) -> None:
        plan = {
            "public": {
                "host": "deepthought",
                "operation": "add",
                "expected_registry_sha256": "a" * 64,
            },
            "request": _request("add", "deepthought", "a" * 64, _host()),
        }
        outcome = {
            "success": True,
            "receipt": {
                "before_registry_sha256": "a" * 64,
                "after_registry_sha256": "b" * 64,
                "receipt_path": "/tmp/receipt.json",
                "readback": {"ok": True},
                "rollback": {"attempted": False, "success": True},
            },
        }
        with patch.object(
            operations.fleet_mutation, "plan_registry_mutation", return_value=plan
        ), patch.object(
            operations.fleet_mutation, "execute_registry_mutation", return_value=outcome
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            operations.base, "_append_audit"
        ):
            result = operations.grabowski_operation_run(
                operations.FLEET_MUTATION_OPERATION,
                {"operation": "add"},
            )
        require_mutation.assert_called_once_with("terminal_execute", opaque_command=False)
        self.assertTrue(result["success"])
        self.assertEqual(
            result["results"][0]["typed_action"],
            operations.FLEET_MUTATION_OPERATION,
        )
        self.assertTrue(result["audit"]["secondary_audit_recorded"])

    def test_secondary_audit_failure_does_not_hide_successful_receipt(self) -> None:
        plan = {
            "public": {
                "host": "deepthought",
                "operation": "add",
                "expected_registry_sha256": "a" * 64,
            },
            "request": _request("add", "deepthought", "a" * 64, _host()),
        }
        outcome = {
            "success": True,
            "receipt": {
                "before_registry_sha256": "a" * 64,
                "after_registry_sha256": "b" * 64,
                "receipt_path": "/tmp/receipt.json",
                "readback": {"ok": True},
                "rollback": {"attempted": False, "success": True},
            },
        }
        with patch.object(
            operations.fleet_mutation, "plan_registry_mutation", return_value=plan
        ), patch.object(
            operations.fleet_mutation, "execute_registry_mutation", return_value=outcome
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations.base, "_append_audit", side_effect=OSError("audit unavailable")
        ):
            result = operations.grabowski_operation_run(
                operations.FLEET_MUTATION_OPERATION,
                {"operation": "add"},
            )
        self.assertTrue(result["success"])
        self.assertFalse(result["audit"]["secondary_audit_recorded"])
        self.assertEqual(result["audit"]["secondary_audit_error_type"], "OSError")

    def test_operation_list_rejects_registry_shadowing_builtin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "operations.json"
            config.write_text(
                json.dumps({
                    "schema_version": 1,
                    "operations": {operations.FLEET_MUTATION_OPERATION: {}},
                }),
                encoding="utf-8",
            )
            with patch.object(operations, "OPERATIONS_CONFIG", config), patch.object(
                operations.operator, "_require_operator_capability"
            ):
                with self.assertRaisesRegex(ValueError, "shadows reserved"):
                    operations.grabowski_operation_list()

    def test_execute_reconciles_lost_worker_response_from_full_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            local = {
                "transport": "local",
                "target": "local",
                "enabled": True,
                "roles": ["operator"],
                "command_allowlist": ["*"],
            }
            before = _write_registry(config, {"heim-pc": local})
            parameters = {
                "operation": "add",
                "host": "deepthought",
                "expected_registry_sha256": _sha256(before),
                "host_spec_json": json.dumps(_host(), sort_keys=True),
            }
            with patch.object(fleet, "FLEET_CONFIG", config), patch.object(
                mutation, "STATE_ROOT", state
            ):
                plan = mutation.plan_registry_mutation(parameters)
                _write_registry(config, {"heim-pc": local, "deepthought": _host()})
                with patch.object(
                    mutation,
                    "_launch_worker",
                    side_effect=mutation.FleetRegistryMutationError("lost response"),
                ):
                    outcome = mutation.execute_registry_mutation(plan)
            self.assertTrue(outcome["success"])
            self.assertEqual(
                outcome["reconciliation"]["outcome_state"],
                "parent_readback_reconciled",
            )
            self.assertTrue(outcome["reconciliation"]["target_satisfied"])
            self.assertTrue(outcome["reconciliation"]["unaffected_hosts_preserved"])
            self.assertFalse(outcome["reconciliation"]["retry_safe"])
            self.assertEqual(outcome["receipt"]["receipt_source"], "parent-reconciliation")
            self.assertTrue(Path(outcome["receipt"]["receipt_path"]).is_file())

    def test_execute_refuses_success_when_non_target_host_drifted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            local = {
                "transport": "local",
                "target": "local",
                "enabled": True,
                "roles": ["operator"],
                "command_allowlist": ["*"],
            }
            before = _write_registry(config, {"heim-pc": local})
            parameters = {
                "operation": "add",
                "host": "deepthought",
                "expected_registry_sha256": _sha256(before),
                "host_spec_json": json.dumps(_host(), sort_keys=True),
            }
            with patch.object(fleet, "FLEET_CONFIG", config), patch.object(
                mutation, "STATE_ROOT", state
            ):
                plan = mutation.plan_registry_mutation(parameters)
                changed_local = dict(local)
                changed_local["roles"] = ["operator", "changed"]
                _write_registry(
                    config,
                    {"heim-pc": changed_local, "deepthought": _host()},
                )
                with patch.object(
                    mutation,
                    "_launch_worker",
                    side_effect=mutation.FleetRegistryMutationError("lost response"),
                ):
                    outcome = mutation.execute_registry_mutation(plan)
            self.assertFalse(outcome["success"])
            self.assertTrue(outcome["reconciliation"]["target_satisfied"])
            self.assertFalse(outcome["reconciliation"]["unaffected_hosts_preserved"])
            self.assertFalse(outcome["reconciliation"]["retry_safe"])

    def test_execute_confirms_exact_worker_receipt_and_readback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            state = root / "state"
            before = _write_registry(config, {})
            parameters = {
                "operation": "add",
                "host": "deepthought",
                "expected_registry_sha256": _sha256(before),
                "host_spec_json": json.dumps(_host(), sort_keys=True),
            }
            with patch.object(fleet, "FLEET_CONFIG", config), patch.object(
                mutation, "STATE_ROOT", state
            ):
                plan = mutation.plan_registry_mutation(parameters)

                def launch(request):
                    receipt = mutation.mutate_registry(
                        request, path=config, state_root=state
                    )
                    return {
                        "worker_result": {"returncode": 0},
                        "receipt": receipt,
                    }

                with patch.object(mutation, "_launch_worker", side_effect=launch):
                    outcome = mutation.execute_registry_mutation(plan)
            self.assertTrue(outcome["success"])
            self.assertEqual(
                outcome["reconciliation"]["outcome_state"],
                "worker_receipt_confirmed",
            )
            self.assertTrue(
                outcome["reconciliation"]["receipt_after_hash_matches_current"]
            )

    def test_execute_rejects_tampered_private_preimage_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "fleet.json"
            before = _write_registry(config, {})
            parameters = {
                "operation": "add",
                "host": "deepthought",
                "expected_registry_sha256": _sha256(before),
                "host_spec_json": json.dumps(_host(), sort_keys=True),
            }
            with patch.object(fleet, "FLEET_CONFIG", config):
                plan = mutation.plan_registry_mutation(parameters)
                plan["preimage_bytes"] = b"{}\n"
                with self.assertRaisesRegex(
                    mutation.FleetRegistryMutationError, "private preimage hash mismatch"
                ):
                    mutation.execute_registry_mutation(plan)


if __name__ == "__main__":
    unittest.main()
