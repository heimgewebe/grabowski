from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from src import grabowski_authority_failover as failover


class _BureauError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class AuthorityFailoverTests(unittest.TestCase):
    def secondary(self):
        return mock.patch.dict(
            os.environ,
            {failover.BRANDING_ENVIRONMENT: "der-kleine-maulwurf"},
            clear=False,
        )

    def fake_effect_interceptor(self, enabled: bool = True) -> types.ModuleType:
        module = types.ModuleType("grabowski_effect_interceptor")
        module.fence_enforcement_required = mock.Mock(return_value=enabled)
        return module

    def fake_bureau_runtime(
        self,
        *,
        repository_error: str | None = None,
        runtime_error: str | None = None,
    ) -> types.ModuleType:
        module = types.ModuleType("grabowski_bureau_leases")
        module.BureauLeaseContractError = _BureauError

        def repository():
            if repository_error:
                raise _BureauError(repository_error)
            return Path("/home/alex/repos/bureau")

        def runtime():
            if runtime_error:
                raise _BureauError(runtime_error)
            return {"python_launcher": Path("/runtime/python")}

        module._validated_bureau_repository_root = repository
        module._contract_runtime = runtime
        return module

    def test_only_secondary_runtime_can_fail_over(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(failover.is_secondary_operator())
            self.assertFalse(
                failover.systemkatalog_failure_is_failover_trigger("root_unavailable")
            )
        with self.secondary():
            self.assertTrue(failover.is_secondary_operator())
            self.assertTrue(
                failover.systemkatalog_failure_is_failover_trigger("root_unavailable")
            )

    def test_systemkatalog_semantic_or_integrity_denials_never_trigger(self) -> None:
        with self.secondary():
            for code in (
                "repository_dirty",
                "origin_unexpected",
                "query_script_missing",
                "payload_contract_mismatch",
                "subprocess_timeout",
                "operation_unsupported",
            ):
                with self.subTest(code=code):
                    self.assertFalse(
                        failover.systemkatalog_failure_is_failover_trigger(code)
                    )

    def test_bureau_missing_local_repository_routes_to_primary(self) -> None:
        fake = self.fake_bureau_runtime(repository_error="bureau-repository-unavailable")
        with self.secondary(), mock.patch.dict(
            sys.modules, {"grabowski_bureau_leases": fake}
        ):
            route = failover.bureau_route(str(failover.PRIMARY_BUREAU_CONTROL_ROOT))
        self.assertEqual(route["route"], "remote-primary")
        self.assertEqual(route["local_code"], "bureau-repository-unavailable")

    def test_bureau_missing_runtime_routes_to_primary(self) -> None:
        fake = self.fake_bureau_runtime(runtime_error="contract-executable-unavailable")
        with self.secondary(), mock.patch.dict(
            sys.modules, {"grabowski_bureau_leases": fake}
        ):
            route = failover.bureau_route(str(failover.PRIMARY_BUREAU_CONTROL_ROOT))
        self.assertEqual(route["route"], "remote-primary")
        self.assertEqual(route["local_code"], "contract-executable-unavailable")

    def test_bureau_integrity_denial_does_not_fail_over(self) -> None:
        fake = self.fake_bureau_runtime(repository_error="control-checkout-remote-mismatch")
        with self.secondary(), mock.patch.dict(
            sys.modules, {"grabowski_bureau_leases": fake}
        ):
            route = failover.bureau_route(str(failover.PRIMARY_BUREAU_CONTROL_ROOT))
        self.assertEqual(route["route"], "local")
        self.assertEqual(route["local_code"], "control-checkout-remote-mismatch")

    def test_caller_specific_registry_root_is_never_relayed(self) -> None:
        fake = self.fake_bureau_runtime(repository_error="bureau-repository-unavailable")
        with self.secondary(), mock.patch.dict(
            sys.modules, {"grabowski_bureau_leases": fake}
        ):
            route = failover.bureau_route("/tmp/caller-selected-registry")
        self.assertEqual(route["route"], "local")
        self.assertEqual(route["reason"], "caller-specific-registry-root")

    def test_bureau_request_rejects_noncanonical_remote_registry(self) -> None:
        with self.assertRaises(failover.AuthorityRelayError) as raised:
            failover._request(
                "bureau",
                "task_publish_preview",
                {"proposal_id": "a" * 64, "registry_root": "/tmp/other"},
            )
        self.assertEqual(raised.exception.code, "registry_root_not_canonical")

    def test_relay_binds_response_to_request_and_runtime(self) -> None:
        arguments = {"operation": "system", "value": "bureau"}
        _request, _payload, request_sha256 = failover._request(
            "systemkatalog", "query", arguments
        )
        remote_result = {
            "schema_version": 1,
            "kind": "grabowski.systemkatalog_query",
            "status": "ok",
            "systemkatalog": {"result": {"id": "bureau"}},
        }
        response = {
            "schema_version": failover.SCHEMA_VERSION,
            "kind": failover.RESPONSE_KIND,
            "authority": "systemkatalog",
            "operation": "query",
            "request_sha256": request_sha256,
            "runtime_binding": {
                "release_id": "release-test",
                "repo_head": "a" * 40,
                "relay_source_sha256": "b" * 64,
                "provenance_valid": True,
                "runtime_binding_valid": True,
                "artifact_integrity_valid": True,
            },
            "result": remote_result,
        }
        fleet = types.ModuleType("grabowski_fleet")
        run = mock.Mock(
            return_value={
                "result": {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                    "stdout": failover._canonical_json(response).decode("utf-8"),
                    "stderr": "",
                }
            }
        )
        fleet.run_fleet_host = run
        with self.secondary(), mock.patch.dict(sys.modules, {"grabowski_fleet": fleet}):
            result = failover.relay_systemkatalog("system", "bureau")
        self.assertEqual(result["status"], "ok")
        evidence = result["authority_failover"]
        self.assertEqual(evidence["route"], "remote-primary")
        self.assertEqual(evidence["authority_host"], "heim-pc")
        self.assertEqual(evidence["request_sha256"], request_sha256)
        self.assertEqual(evidence["automatic_failback"], "local-first-next-call")
        remote_argv = run.call_args.args[1]
        self.assertEqual(remote_argv[0], str(failover.PRIMARY_RUNTIME_PYTHON))
        self.assertEqual(remote_argv[1:3], ["-I", "-c"])
        self.assertEqual(remote_argv[3], failover.REMOTE_BOOTSTRAP_CODE)
        self.assertNotIn("sys.path.insert", failover.REMOTE_BOOTSTRAP_CODE)

    def test_runtime_binding_requires_primary_provenance(self) -> None:
        runtime = types.ModuleType("grabowski_mcp")
        runtime._deployment_metadata = mock.Mock(
            return_value={
                "completion_status": "complete",
                "provenance_valid": False,
                "runtime_binding_valid": True,
                "artifact_integrity_valid": True,
            }
        )
        with mock.patch.dict(sys.modules, {"grabowski_mcp": runtime}):
            with self.assertRaises(failover.AuthorityRelayError) as raised:
                failover._runtime_binding()
        self.assertEqual(raised.exception.code, "primary_runtime_integrity_invalid")

    def test_runtime_binding_binds_installed_relay_source(self) -> None:
        source_sha256 = failover._sha256(Path(failover.__file__).read_bytes())
        runtime = types.ModuleType("grabowski_mcp")
        runtime._deployment_metadata = mock.Mock(
            return_value={
                "completion_status": "complete",
                "provenance_valid": True,
                "runtime_binding_valid": True,
                "artifact_integrity_valid": True,
                "release_id": "release-test",
                "repo_head": "a" * 40,
                "source_identity_by_module": {
                    "grabowski_authority_failover": True,
                },
                "source_sha256s": {
                    "grabowski_authority_failover": source_sha256,
                },
            }
        )
        with mock.patch.dict(sys.modules, {"grabowski_mcp": runtime}):
            binding = failover._runtime_binding()
        self.assertEqual(binding["relay_source_sha256"], source_sha256)
        self.assertTrue(binding["provenance_valid"])
        self.assertTrue(binding["runtime_binding_valid"])
        self.assertTrue(binding["artifact_integrity_valid"])

    def test_remote_integrity_failure_blocks_before_dispatch(self) -> None:
        _request, payload, _request_sha256 = failover._request(
            "systemkatalog",
            "query",
            {"operation": "system", "value": "bureau"},
        )
        encoded = base64.b64encode(payload).decode("ascii")
        failure = failover.AuthorityRelayError(
            "primary_runtime_integrity_invalid",
            "primary runtime invalid",
        )
        with (
            mock.patch.object(failover, "is_secondary_operator", return_value=False),
            mock.patch.object(failover.Path, "home", return_value=failover.PRIMARY_HOME),
            mock.patch.object(failover, "_runtime_binding", side_effect=failure),
            mock.patch.object(failover, "_dispatch_remote") as dispatch,
            mock.patch("builtins.print"),
        ):
            returncode = failover.remote_main(encoded)
        self.assertEqual(returncode, 2)
        dispatch.assert_not_called()

    def test_response_request_mismatch_fails_closed(self) -> None:
        response = {
            "schema_version": failover.SCHEMA_VERSION,
            "kind": failover.RESPONSE_KIND,
            "authority": "systemkatalog",
            "operation": "query",
            "request_sha256": "0" * 64,
            "runtime_binding": {
                "release_id": "release-test",
                "repo_head": "a" * 40,
                "relay_source_sha256": "b" * 64,
                "provenance_valid": True,
                "runtime_binding_valid": True,
                "artifact_integrity_valid": True,
            },
            "result": {"status": "ok"},
        }
        fleet = types.ModuleType("grabowski_fleet")
        fleet.run_fleet_host = mock.Mock(
            return_value={
                "result": {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                    "stdout": failover._canonical_json(response).decode("utf-8"),
                    "stderr": "",
                }
            }
        )
        with self.secondary(), mock.patch.dict(sys.modules, {"grabowski_fleet": fleet}):
            with self.assertRaises(failover.AuthorityRelayError) as raised:
                failover.relay_systemkatalog("system", "bureau")
        self.assertEqual(raised.exception.code, "relay_response_contract_mismatch")

    def test_mutating_transport_loss_is_marked_dispatched(self) -> None:
        fleet = types.ModuleType("grabowski_fleet")
        fleet.run_fleet_host = mock.Mock(side_effect=OSError("transport down"))
        arguments = {"request": {"schema_version": 1, "operation": "record"}}
        effect = self.fake_effect_interceptor(True)
        with self.secondary(), mock.patch.dict(
            sys.modules,
            {"grabowski_fleet": fleet, "grabowski_effect_interceptor": effect},
        ):
            with self.assertRaises(failover.AuthorityRelayError) as raised:
                failover.relay_bureau("candidate_record", arguments, mutation=True)
        self.assertEqual(raised.exception.code, "relay_transport_failed")
        self.assertTrue(raised.exception.dispatched)

    def test_mutating_relay_requires_active_fence_enforcement(self) -> None:
        fleet = types.ModuleType("grabowski_fleet")
        fleet.run_fleet_host = mock.Mock()
        effect = self.fake_effect_interceptor(False)
        arguments = {"request": {"schema_version": 1, "operation": "record"}}
        with self.secondary(), mock.patch.dict(
            sys.modules,
            {"grabowski_fleet": fleet, "grabowski_effect_interceptor": effect},
        ):
            with self.assertRaises(failover.AuthorityRelayError) as raised:
                failover.relay_bureau("candidate_record", arguments, mutation=True)
        self.assertEqual(raised.exception.code, "relay_fence_required")
        self.assertFalse(raised.exception.dispatched)
        fleet.run_fleet_host.assert_not_called()

    def test_clean_remote_refusal_does_not_become_ambiguity(self) -> None:
        refusal = {
            "schema_version": failover.SCHEMA_VERSION,
            "kind": failover.ERROR_KIND,
            "code": "remote_proposal_missing",
            "message": "refused",
            "details": {},
            "effect_dispatched": False,
        }
        fleet = types.ModuleType("grabowski_fleet")
        fleet.run_fleet_host = mock.Mock(
            return_value={
                "result": {
                    "returncode": 2,
                    "timed_out": False,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                    "stdout": failover._canonical_json(refusal).decode("utf-8"),
                    "stderr": "",
                }
            }
        )
        effect = self.fake_effect_interceptor(True)
        arguments = {
            "proposal_id": "a" * 64,
            "reviewer": "reviewer",
            "proposal_sha256": "b" * 64,
            "registry_root": str(failover.PRIMARY_BUREAU_CONTROL_ROOT),
        }
        with self.secondary(), mock.patch.dict(
            sys.modules,
            {"grabowski_fleet": fleet, "grabowski_effect_interceptor": effect},
        ):
            with self.assertRaises(failover.AuthorityRelayError) as raised:
                failover.relay_bureau("task_review", arguments, mutation=True)
        self.assertEqual(raised.exception.code, "relay_remote_refused")
        self.assertEqual(raised.exception.details["remote_code"], "remote_proposal_missing")
        self.assertFalse(raised.exception.dispatched)

    def test_candidate_record_extra_field_rejected_before_transport(self) -> None:
        with self.assertRaises(failover.AuthorityRelayError) as raised:
            failover._request(
                "bureau",
                "candidate_record",
                {"request": {"schema_version": 1, "acceptance_criteria": ["x"]}},
            )
        self.assertEqual(raised.exception.code, "arguments_contract_mismatch")
        self.assertEqual(raised.exception.details["argument"], "request")

    def test_bureau_argument_type_contract_covers_all_operations(self) -> None:
        self.assertEqual(set(failover.BUREAU_ARGUMENT_TYPES), set(failover.BUREAU_OPERATIONS))
        for operation, (_function, keys) in failover.BUREAU_OPERATIONS.items():
            with self.subTest(operation=operation):
                self.assertEqual(set(failover.BUREAU_ARGUMENT_TYPES[operation]), set(keys))

    def test_wrong_bureau_argument_type_fails_closed(self) -> None:
        with self.assertRaises(failover.AuthorityRelayError) as raised:
            failover._request(
                "bureau",
                "task_publish",
                {
                    "proposal_id": "a" * 64,
                    "registry_root": str(failover.PRIMARY_BUREAU_CONTROL_ROOT),
                    "lease_ttl_seconds": "240",
                },
            )
        self.assertEqual(raised.exception.code, "arguments_contract_mismatch")
        self.assertEqual(raised.exception.details["argument"], "lease_ttl_seconds")

    def test_systemkatalog_argument_types_fail_closed(self) -> None:
        for arguments in (
            {"operation": {"bad": True}, "value": None},
            {"operation": "system", "value": 5},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(failover.AuthorityRelayError) as raised:
                    failover._request("systemkatalog", "query", arguments)
                self.assertEqual(raised.exception.code, "arguments_contract_mismatch")

    def test_large_remote_result_is_compacted_with_digest(self) -> None:
        original = {
            "schema_version": 1,
            "kind": "bureau_task_publication_receipt",
            "status": "published",
            "effect_started": True,
            "blob": "x" * 3_000_000,
        }
        compact = failover._compact_remote_result(original)
        self.assertTrue(compact["relay_compacted"])
        self.assertEqual(
            compact["remote_result_sha256"],
            failover._sha256(failover._canonical_json(original)),
        )
        self.assertLessEqual(
            len(failover._canonical_json(compact)),
            failover.MAX_RELAY_RESULT_BYTES,
        )
        self.assertEqual(compact["status"], "published")

    def test_primary_missing_proposal_refuses_before_dispatch(self) -> None:
        request, payload, _digest = failover._request(
            "bureau",
            "task_review",
            {
                "proposal_id": "a" * 64,
                "reviewer": "reviewer",
                "proposal_sha256": "b" * 64,
                "registry_root": str(failover.PRIMARY_BUREAU_CONTROL_ROOT),
            },
        )
        encoded = base64.b64encode(payload).decode("ascii")
        intake = types.ModuleType("grabowski_bureau_intake")
        intake.grabowski_bureau_task_review = mock.Mock()
        intake._proposal_directory = mock.Mock(return_value=Path("/definitely/missing/proposal"))
        binding = {
            "release_id": "release-test",
            "repo_head": "a" * 40,
            "relay_source_sha256": "b" * 64,
            "provenance_valid": True,
            "runtime_binding_valid": True,
            "artifact_integrity_valid": True,
        }
        with (
            mock.patch.object(failover, "is_secondary_operator", return_value=False),
            mock.patch.object(failover.Path, "home", return_value=failover.PRIMARY_HOME),
            mock.patch.object(failover, "_runtime_binding", return_value=binding),
            mock.patch.object(failover, "_dispatch_remote") as dispatch,
            mock.patch.dict(sys.modules, {"grabowski_bureau_intake": intake}),
            mock.patch("builtins.print") as printed,
        ):
            returncode = failover.remote_main(encoded)
        self.assertEqual(returncode, 2)
        dispatch.assert_not_called()
        envelope = json.loads(printed.call_args.args[0])
        self.assertEqual(envelope["code"], "remote_proposal_missing")
        self.assertFalse(envelope["effect_dispatched"])

    def test_read_transport_loss_is_not_an_effect_claim(self) -> None:
        fleet = types.ModuleType("grabowski_fleet")
        fleet.run_fleet_host = mock.Mock(side_effect=OSError("transport down"))
        with self.secondary(), mock.patch.dict(sys.modules, {"grabowski_fleet": fleet}):
            with self.assertRaises(failover.AuthorityRelayError) as raised:
                failover.relay_systemkatalog("system", "bureau")
        self.assertFalse(raised.exception.dispatched)

    def test_remote_request_requires_canonical_json(self) -> None:
        request = {
            "schema_version": 1,
            "kind": failover.REQUEST_KIND,
            "authority": "systemkatalog",
            "operation": "query",
            "arguments": {"operation": "system", "value": "bureau"},
        }
        noncanonical = json.dumps(request, indent=2).encode("utf-8")
        encoded = base64.b64encode(noncanonical).decode("ascii")
        with self.assertRaises(failover.AuthorityRelayError) as raised:
            failover._decode_remote_request(encoded)
        self.assertEqual(raised.exception.code, "request_not_canonical")


if __name__ == "__main__":
    unittest.main()
