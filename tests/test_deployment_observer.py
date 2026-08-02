from __future__ import annotations

import asyncio
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

import grabowski_deployment_observer as observer
from tests.test_operator_contract import _load_operator_module
from tests.test_self_deploy import SELF_DEPLOY, _source_identity
from tests.test_dual_service_deploy import core as deploy_core, dual


UNIT = "grabowski-job-abcdef012345"
HEAD = "b" * 40
SOURCE_SHA = "c" * 64
ARGV_SHA = "d" * 64
ORIGIN_SHA = "e" * 64
CLIENT_ID = "client-t131"
ISSUED = 1_000


def _metadata(*, unit: str = UNIT) -> dict[str, object]:
    return {
        "schema_version": 2,
        "unit": unit,
        "argv": [
            "/usr/bin/python3",
            "/runtime/run_scheduled_deploy.py",
            "--expected-head",
            HEAD,
            "--source-identity-sha256",
            SOURCE_SHA,
        ],
        "argv_sha256": ARGV_SHA,
        "origin_sha256": ORIGIN_SHA,
        "finalization_contract": {
            "unit": unit,
            "expected_head": HEAD,
            "argv_sha256": ARGV_SHA,
        },
    }


def _marker(*, token: str = "f" * 64, created: int = ISSUED + 1) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "grabowski_deployment_admission_drain",
        "token": token,
        "expected_head": HEAD,
        "source_identity_sha256": SOURCE_SHA,
        "created_at_unix": created,
        "expires_at_unix": created + 600,
    }


def _contract(
    capability: str,
    *,
    client_id: str | None = CLIENT_ID,
    issued_at_unix: int = ISSUED,
) -> dict[str, object]:
    return observer.build_contract(
        unit=UNIT,
        capability=capability,
        client_id=client_id,
        expected_head=HEAD,
        source_identity_sha256=SOURCE_SHA,
        argv_sha256=ARGV_SHA,
        origin_sha256=ORIGIN_SHA,
        issued_at_unix=issued_at_unix,
    )


class DeploymentObserverContractTests(unittest.TestCase):
    def test_contract_stores_only_hash_and_authorizes_exact_request(self) -> None:
        capability = "a" * 64
        contract = _contract(capability)
        self.assertNotIn(capability, json.dumps(contract, sort_keys=True))
        self.assertEqual(
            hashlib.sha256(capability.encode("ascii")).hexdigest(),
            contract["capability_sha256"],
        )
        evidence = observer.authorize_request(
            contract,
            metadata=_metadata(),
            capability=capability,
            client_id=CLIENT_ID,
            now_unix=ISSUED + 5,
        )
        self.assertEqual(UNIT, evidence["unit"])
        self.assertTrue(evidence["client_id_bound"])
        self.assertEqual(observer.OPERATION, evidence["operation"])

    def test_capability_client_and_job_drift_fail_closed(self) -> None:
        capability = "a" * 64
        contract = _contract(capability)
        cases = (
            ("wrong capability", {"capability": "9" * 64, "client_id": CLIENT_ID, "metadata": _metadata()}),
            ("wrong client", {"capability": capability, "client_id": "other-client", "metadata": _metadata()}),
            ("wrong unit", {"capability": capability, "client_id": CLIENT_ID, "metadata": _metadata(unit="grabowski-job-111111111111")}),
        )
        for label, values in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    observer.authorize_request(
                        contract,
                        metadata=values["metadata"],
                        capability=values["capability"],
                        client_id=values["client_id"],
                        now_unix=ISSUED + 5,
                    )

    def test_head_source_argv_origin_and_expiry_drift_fail_closed(self) -> None:
        capability = "a" * 64
        contract = _contract(capability)
        mutations = (
            ("expected_head", lambda metadata: metadata["finalization_contract"].__setitem__("expected_head", "1" * 40)),
            ("source", lambda metadata: metadata["argv"].__setitem__(5, "2" * 64)),
            ("argv", lambda metadata: metadata.__setitem__("argv_sha256", "3" * 64)),
            ("origin", lambda metadata: metadata.__setitem__("origin_sha256", "4" * 64)),
        )
        for label, mutate in mutations:
            metadata = _metadata()
            mutate(metadata)
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    observer.authorize_request(
                        contract,
                        metadata=metadata,
                        capability=capability,
                        client_id=CLIENT_ID,
                        now_unix=ISSUED + 5,
                    )
        with self.assertRaisesRegex(ValueError, "not current"):
            observer.authorize_request(
                contract,
                metadata=_metadata(),
                capability=capability,
                client_id=CLIENT_ID,
                now_unix=ISSUED + observer.CAPABILITY_LIFETIME_SECONDS + 1,
            )

    def test_activation_is_private_create_only_and_marker_bound(self) -> None:
        capability = "a" * 64
        metadata = _metadata()
        contract = _contract(capability)
        marker = _marker()
        binding = observer.build_activation_binding(
            contract,
            metadata=metadata,
            marker=marker,
            now_unix=ISSUED + 1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            path = observer.activation_path(directory)
            observer.create_activation(path, binding)
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            observed = observer.read_activation(path)
            self.assertEqual(
                binding,
                observer.validate_activation_binding(
                    observed,
                    contract_value=contract,
                    metadata=metadata,
                    marker=marker,
                    now_unix=ISSUED + 2,
                ),
            )
            with self.assertRaises(FileExistsError):
                observer.create_activation(path, binding)
            with self.assertRaisesRegex(ValueError, "marker_token_sha256"):
                observer.validate_activation_binding(
                    observed,
                    contract_value=contract,
                    metadata=metadata,
                    marker=_marker(token="8" * 64),
                    now_unix=ISSUED + 2,
                )

        with tempfile.TemporaryDirectory() as temporary:
            public_directory = Path(temporary)
            public_directory.chmod(0o755)
            with self.assertRaisesRegex(PermissionError, "parent is unsafe"):
                observer.create_activation(
                    observer.activation_path(public_directory),
                    binding,
                )


class DeploymentObserverGateTests(unittest.TestCase):
    def _active_observer_fixture(self):
        operator = _load_operator_module()
        capability = "a" * 64
        metadata = _metadata()
        current = int(time.time())
        contract = _contract(capability, issued_at_unix=current - 1)
        metadata["deployment_observer_contract"] = contract
        marker_payload = _marker(created=current - 1)
        marker_payload["expires_at_unix"] = int(time.time()) + 600
        marker_observation = {
            **marker_payload,
            "state": "active",
            "active": True,
            "valid": True,
            "path": "/state/deployment-admission-drain.json",
        }
        temporary = tempfile.TemporaryDirectory()
        directory = Path(temporary.name)
        directory.chmod(0o700)
        binding = observer.build_activation_binding(
            contract,
            metadata=metadata,
            marker=marker_payload,
            now_unix=int(time.time()),
        )
        observer.create_activation(observer.activation_path(directory), binding)
        context = types.SimpleNamespace(client_id=CLIENT_ID)
        return operator, capability, metadata, marker_observation, directory, context, temporary

    def test_exact_active_observer_does_not_increment_admission_counter(self) -> None:
        (
            operator,
            capability,
            metadata,
            marker,
            directory,
            context,
            temporary,
        ) = self._active_observer_fixture()
        try:
            operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
                is_async=False,
                context_kwarg="ctx",
            )
            with patch.object(operator, "_read_job_metadata", return_value=metadata), patch.object(
                operator, "_job_directory", return_value=directory
            ), patch.object(operator, "_read_deployment_admission_marker", return_value=marker):
                operator._configure_http_runtime()
                result = asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        observer.OPERATION,
                        {
                            "unit": UNIT,
                            "deployment_observer_capability": capability,
                        },
                        context,
                    )
                )
                self.assertTrue(result["called"])
                self.assertEqual(0, operator._deployment_admission_active_tool_calls())
        finally:
            temporary.cleanup()

    def test_pre_marker_observer_remains_a_normal_counted_read(self) -> None:
        operator = _load_operator_module()
        capability = "a" * 64
        current = int(time.time())
        metadata = _metadata()
        metadata["deployment_observer_contract"] = _contract(
            capability, issued_at_unix=current - 1
        )
        marker = {
            "schema_version": 1,
            "kind": "grabowski_deployment_admission_observation",
            "state": "absent",
            "active": False,
            "valid": True,
            "path": "/state/deployment-admission-drain.json",
        }
        observed_counts: list[int] = []

        async def original(*args, **kwargs):
            observed_counts.append(operator._deployment_admission_active_tool_calls())
            return {"called": True, "args": args, "kwargs": kwargs}

        operator.mcp._tool_manager.call_tool = original
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
        )
        context = types.SimpleNamespace(client_id=CLIENT_ID)
        with patch.object(operator, "_read_job_metadata", return_value=metadata), patch.object(
            operator, "_read_deployment_admission_marker", return_value=marker
        ):
            operator._configure_http_runtime()
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    observer.OPERATION,
                    {
                        "unit": UNIT,
                        "deployment_observer_capability": capability,
                    },
                    context,
                )
            )
        self.assertTrue(result["called"])
        self.assertEqual([1], observed_counts)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_wrong_capability_other_tool_and_missing_activation_remain_blocked(self) -> None:
        (
            operator,
            capability,
            metadata,
            marker,
            directory,
            context,
            temporary,
        ) = self._active_observer_fixture()
        try:
            with patch.object(operator, "_read_job_metadata", return_value=metadata), patch.object(
                operator, "_job_directory", return_value=directory
            ), patch.object(operator, "_read_deployment_admission_marker", return_value=marker):
                operator._configure_http_runtime()
                for name, arguments in (
                    (
                        observer.OPERATION,
                        {"unit": UNIT, "deployment_observer_capability": "9" * 64},
                    ),
                    (
                        "grabowski_job_logs",
                        {"unit": UNIT, "deployment_observer_capability": capability},
                    ),
                ):
                    with self.subTest(name=name):
                        with self.assertRaisesRegex(RuntimeError, "rejects new tool calls"):
                            asyncio.run(operator.mcp._tool_manager.call_tool(name, arguments, context))
                        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

                observer.activation_path(directory).unlink()
                with self.assertRaisesRegex(RuntimeError, "rejects new tool calls"):
                    asyncio.run(
                        operator.mcp._tool_manager.call_tool(
                            observer.OPERATION,
                            {"unit": UNIT, "deployment_observer_capability": capability},
                            context,
                        )
                    )
                self.assertEqual(0, operator._deployment_admission_active_tool_calls())
        finally:
            temporary.cleanup()


class RuntimeDeployScheduleObserverTests(unittest.TestCase):
    def test_scheduler_returns_raw_capability_but_stores_only_hash(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        expected = "7" * 40
        identity = _source_identity(repo, expected)
        unit = UNIT
        job_directory = Path("/state") / unit
        command = SELF_DEPLOY._deploy_command(
            repo,
            runner,
            expected,
            9,
            canonical_repository=repo,
            source_kind="canonical-main",
            source_identity_sha256=identity["identity_sha256"],
        )
        captured: dict[str, object] = {}

        def start_job(*args, **kwargs):
            request = kwargs["deployment_observer_request"]
            contract = observer.build_contract(
                unit=unit,
                capability=request["capability"],
                client_id=request["client_id"],
                expected_head=request["expected_head"],
                source_identity_sha256=request["source_identity_sha256"],
                argv_sha256=SELF_DEPLOY.operator._argv_hash(command),
                origin_sha256="8" * 64,
                issued_at_unix=int(time.time()),
            )
            captured["request"] = request
            return {
                "unit": unit,
                "argv_sha256": SELF_DEPLOY.operator._argv_hash(command),
                "origin_sha256": "8" * 64,
                "metadata_path": str(job_directory / "metadata.json"),
                "stdout_path": str(job_directory / "stdout.log"),
                "stderr_path": str(job_directory / "stderr.log"),
                "deployment_observer_contract": contract,
            }

        class Context:
            client_id = CLIENT_ID

        fixed_uuid = Mock(hex="abcdef012345ffffffffffffffffffff")
        with patch.object(
            SELF_DEPLOY,
            "_deployment_source_preflight",
            return_value=(repo, runner, identity),
        ), patch.object(
            SELF_DEPLOY, "_deploy_schedule_lock", return_value=nullcontext()
        ), patch.object(
            SELF_DEPLOY, "_matching_inflight_deploy_job", return_value=None
        ), patch.object(
            SELF_DEPLOY.operator, "_jobs_root", return_value=Path("/state")
        ), patch.object(
            SELF_DEPLOY, "_deploy_index", return_value={"units": [], "pending_unit": None}
        ), patch.object(
            SELF_DEPLOY, "_write_deploy_index"
        ), patch.object(
            SELF_DEPLOY.uuid, "uuid4", return_value=fixed_uuid
        ), patch.object(
            SELF_DEPLOY.operator, "_start_job", side_effect=start_job
        ), patch.object(
            SELF_DEPLOY.base, "_append_audit"
        ):
            result = SELF_DEPLOY.grabowski_runtime_deploy_schedule(
                expected,
                9,
                ctx=Context(),
            )
        request = captured["request"]
        capability = result["deployment_observer"]["capability"]
        self.assertEqual(request["capability"], capability)
        self.assertTrue(result["deployment_observer"]["available"])
        contract = observer.build_contract(
            unit=unit,
            capability=capability,
            client_id=CLIENT_ID,
            expected_head=expected,
            source_identity_sha256=identity["identity_sha256"],
            argv_sha256=SELF_DEPLOY.operator._argv_hash(command),
            origin_sha256="8" * 64,
            issued_at_unix=int(time.time()),
        )
        self.assertNotIn(capability, json.dumps(contract, sort_keys=True))
        self.assertEqual(contract["contract_sha256"], result["deployment_observer"]["contract_sha256"])
        self.assertEqual(
            hashlib.sha256(capability.encode("ascii")).hexdigest(),
            contract["capability_sha256"],
        )


class DualDeployObserverActivationTests(unittest.TestCase):
    def test_dual_deploy_activates_exact_job_contract_after_marker_creation(self) -> None:
        capability = "a" * 64
        current = int(time.time())
        metadata = _metadata()
        contract = _contract(capability, issued_at_unix=current - 1)
        metadata["deployment_observer_contract"] = contract
        marker = _marker(created=current - 1)
        marker["expires_at_unix"] = current + 600
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary)
            job_directory = state_root / "jobs" / UNIT
            job_directory.mkdir(parents=True, mode=0o700)
            metadata_path = job_directory / "metadata.json"
            metadata_path.write_text(
                json.dumps(metadata, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            metadata_path.chmod(0o600)
            with patch.object(dual.core, "DEFAULT_STATE_ROOT", state_root), patch.dict(
                os.environ,
                {
                    "GRABOWSKI_JOB_UNIT": UNIT,
                    "GRABOWSKI_JOB_DIRECTORY": str(job_directory),
                    "GRABOWSKI_JOB_METADATA_PATH": str(metadata_path),
                },
            ):
                evidence = dual._activate_runtime_deploy_observer(marker)
            activation_path = observer.activation_path(job_directory)
            self.assertTrue(activation_path.is_file())
            self.assertEqual(0o600, stat.S_IMODE(activation_path.stat().st_mode))
            observed = observer.read_activation(activation_path)
            validated = observer.validate_activation_binding(
                observed,
                contract_value=contract,
                metadata=metadata,
                marker=marker,
                now_unix=current,
            )
            self.assertEqual(validated["binding_sha256"], evidence["binding_sha256"])

    def test_watchdog_or_legacy_marker_without_job_contract_creates_no_activation(self) -> None:
        with patch.dict(
            os.environ,
            {
                "GRABOWSKI_JOB_UNIT": "",
                "GRABOWSKI_JOB_DIRECTORY": "",
                "GRABOWSKI_JOB_METADATA_PATH": "",
            },
        ):
            with self.assertRaises(deploy_core.DeployError):
                dual._activate_runtime_deploy_observer(_marker())
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(dual._activate_runtime_deploy_observer(_marker()))
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(
                os.environ,
                {"GRABOWSKI_JOB_DIRECTORY": temporary},
                clear=True,
            ):
                self.assertIsNone(
                    dual._activate_runtime_deploy_observer(_marker())
                )

    def test_unrelated_grabowski_job_without_contract_creates_no_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            job_directory = Path(temporary) / UNIT
            job_directory.mkdir(parents=True, mode=0o700)
            metadata_path = job_directory / "metadata.json"
            metadata = _metadata()
            metadata_path.write_text(
                json.dumps(metadata, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            metadata_path.chmod(0o600)
            with patch.dict(
                os.environ,
                {
                    "GRABOWSKI_JOB_UNIT": UNIT,
                    "GRABOWSKI_JOB_DIRECTORY": str(job_directory),
                    "GRABOWSKI_JOB_METADATA_PATH": str(metadata_path),
                },
            ):
                self.assertIsNone(dual._activate_runtime_deploy_observer(_marker()))
            self.assertFalse(observer.activation_path(job_directory).exists())

    def test_metadata_path_drift_fails_closed_before_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary)
            other = state_root / "other.json"
            other.write_text("{}\n", encoding="utf-8")
            other.chmod(0o600)
            with patch.object(dual.core, "DEFAULT_STATE_ROOT", state_root), patch.dict(
                os.environ,
                {
                    "GRABOWSKI_JOB_UNIT": UNIT,
                    "GRABOWSKI_JOB_DIRECTORY": str(state_root / "jobs" / UNIT),
                    "GRABOWSKI_JOB_METADATA_PATH": str(other),
                },
            ):
                with self.assertRaises(deploy_core.DeployError):
                    dual._activate_runtime_deploy_observer(_marker())


if __name__ == "__main__":
    unittest.main()
