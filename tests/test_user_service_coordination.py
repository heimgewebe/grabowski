from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch


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


import grabowski_operator as operator  # noqa: E402
import grabowski_resources as real_resources  # noqa: E402


def _result(*, stdout: str = "", returncode: int = 0, timed_out: bool = False) -> dict:
    return {
        "stdout": stdout,
        "stderr": "",
        "returncode": returncode,
        "timed_out": timed_out,
    }


def _reconciliation(*, fragment: str, job: str = "") -> str:
    return "\n".join(
        [
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=running",
            "UnitFileState=enabled",
            f"Job={job}",
            f"FragmentPath={fragment}",
            "",
        ]
    )


def _fake_resources() -> types.ModuleType:
    module = types.ModuleType("grabowski_resources")

    def acquire(owner_id, resource_keys, **_kwargs):
        return {
            "owner_id": owner_id,
            "leases": [
                {
                    "resource_key": key,
                    "owner_id": owner_id,
                    "acquired_at_unix": 100,
                    "updated_at_unix": 100,
                    "expires_at_unix": 400,
                    "metadata_sha256": "a" * 64,
                    "reclaimed_from_owner": None,
                }
                for key in sorted(resource_keys)
            ],
        }

    def renew(owner_id, resource_keys, *, ttl_seconds, expected_leases):
        renewed = [
            {
                **item,
                "updated_at_unix": 200,
                "expires_at_unix": 200 + ttl_seconds,
            }
            for item in expected_leases
        ]
        return {
            "owner_id": owner_id,
            "resource_keys": sorted(resource_keys),
            "expires_at_unix": min(item["expires_at_unix"] for item in renewed),
            "leases": renewed,
        }

    fence_state: dict[str, dict | None] = {"active": None}

    def uncertainty_status(resource_keys=()):
        fence = fence_state["active"]
        if fence is None:
            return None
        if resource_keys and not set(resource_keys).intersection(fence["resource_keys"]):
            return None
        return dict(fence)

    def prepare_fence(owner_id, resource_keys, *, expected_leases, unit, action):
        fence = {
            "fence_id": "f" * 32,
            "owner_id": owner_id,
            "unit": unit,
            "action": action,
            "phase": "prepared",
            "resource_keys": sorted(resource_keys),
            "lease_snapshots": list(expected_leases),
            "cleared_at_unix": None,
        }
        fence_state["active"] = fence
        return dict(fence)

    def update_fence(fence_id, *, phase):
        fence = fence_state["active"]
        if fence is None or fence["fence_id"] != fence_id:
            raise RuntimeError("fence changed")
        fence = {**fence, "phase": phase}
        fence_state["active"] = fence
        return dict(fence)

    def clear_fence(fence_id, *, outcome, evidence_sha256):
        del outcome, evidence_sha256
        fence = fence_state["active"]
        if fence is None or fence["fence_id"] != fence_id:
            raise RuntimeError("fence changed")
        cleared = {**fence, "cleared_at_unix": 300}
        fence_state["active"] = None
        return cleared

    module.acquire_resources = MagicMock(side_effect=acquire)
    module.inspect_resources = MagicMock(return_value={})
    module.renew_resources = MagicMock(side_effect=renew)
    module.release_resources = MagicMock(
        return_value={
            "owner_id": "ignored",
            "force": False,
            "snapshot_guarded": True,
            "released": [],
        }
    )
    module.user_systemd_uncertainty_status = MagicMock(
        side_effect=uncertainty_status
    )
    module.prepare_user_systemd_uncertainty_fence = MagicMock(
        side_effect=prepare_fence
    )
    module.update_user_systemd_uncertainty_fence = MagicMock(
        side_effect=update_fence
    )
    module.clear_user_systemd_uncertainty_fence = MagicMock(
        side_effect=clear_fence
    )
    module._fence_state = fence_state
    return module


class UserServiceCoordinationTests(unittest.TestCase):
    def test_normal_mutation_acquires_unit_and_fragment_before_effect(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        action_result = _result(stdout="started")
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    action_result,
                ],
            ) as run,
            patch.object(
                operator.uuid,
                "uuid4",
                return_value=types.SimpleNamespace(hex="1" * 32),
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        self.assertIs(result, action_result)
        owner = "operator:user-systemd-" + "1" * 32
        resource_keys = [
            "service:user-systemd:demo.service",
            f"path:{fragment}",
        ]
        resources.acquire_resources.assert_called_once_with(
            owner,
            resource_keys,
            purpose="user systemd restart demo.service",
            ttl_seconds=operator._user_systemd_lease_ttl_seconds(
                operator._USER_SYSTEMD_MUTATION_TIMEOUT_SECONDS
            ),
            metadata={"unit": "demo.service", "action": "restart"},
        )
        self.assertEqual(
            run.call_args_list[-1],
            call(
                ["systemctl", "--user", "restart", "demo.service"],
                cwd=operator.HOME,
                timeout_seconds=operator._USER_SYSTEMD_MUTATION_TIMEOUT_SECONDS,
                max_output_bytes=operator.MAX_OUTPUT_BYTES,
            ),
        )
        resources.renew_resources.assert_not_called()
        resources.release_resources.assert_called_once()

    def test_enable_and_disable_acquire_user_unit_config_scope(self) -> None:
        fragment = "/usr/lib/systemd/user/demo.service"
        xdg_config = Path("/tmp/grabowski-user-systemd-xdg")
        config_root = xdg_config / "systemd" / "user"
        for index, action in enumerate(("enable", "disable"), start=2):
            with self.subTest(action=action):
                resources = _fake_resources()
                action_result = _result(stdout=action)
                with (
                    patch.dict(
                        operator.os.environ,
                        {"XDG_CONFIG_HOME": str(xdg_config)},
                        clear=False,
                    ),
                    patch.dict(sys.modules, {"grabowski_resources": resources}),
                    patch.object(operator, "_require_operator_capability"),
                    patch.object(operator, "_require_operator_mutation"),
                    patch.object(
                        operator,
                        "_run",
                        side_effect=[
                            _result(stdout=fragment + "\n"),
                            _result(stdout=_reconciliation(fragment=fragment)),
                            action_result,
                        ],
                    ),
                    patch.object(
                        operator.uuid,
                        "uuid4",
                        return_value=types.SimpleNamespace(hex=str(index) * 32),
                    ),
                ):
                    result = operator.grabowski_user_service("demo.service", action)

                self.assertIs(result, action_result)
                owner = "operator:user-systemd-" + str(index) * 32
                resource_keys = [
                    "service:user-systemd:demo.service",
                    f"path:{fragment}",
                    f"path:{config_root}",
                ]
                resources.acquire_resources.assert_called_once_with(
                    owner,
                    resource_keys,
                    purpose=f"user systemd {action} demo.service",
                    ttl_seconds=operator._user_systemd_lease_ttl_seconds(
                        operator._USER_SYSTEMD_MUTATION_TIMEOUT_SECONDS
                    ),
                    metadata={
                        "unit": "demo.service",
                        "action": action,
                        "unit_file_config_root": str(config_root),
                    },
                )
                prepared = resources.prepare_user_systemd_uncertainty_fence.call_args
                self.assertEqual(prepared.args[1], resource_keys)
                self.assertEqual(prepared.kwargs["unit"], "demo.service")
                self.assertEqual(prepared.kwargs["action"], action)

    def test_non_unit_file_actions_keep_narrow_authority(self) -> None:
        fragment = "/usr/lib/systemd/user/demo.service"
        xdg_config = Path("/tmp/grabowski-user-systemd-xdg")
        config_key = f"path:{xdg_config / 'systemd' / 'user'}"
        for index, action in enumerate(("start", "stop", "restart"), start=5):
            with self.subTest(action=action):
                resources = _fake_resources()
                with (
                    patch.dict(
                        operator.os.environ,
                        {"XDG_CONFIG_HOME": str(xdg_config)},
                        clear=False,
                    ),
                    patch.dict(sys.modules, {"grabowski_resources": resources}),
                    patch.object(operator, "_require_operator_capability"),
                    patch.object(operator, "_require_operator_mutation"),
                    patch.object(
                        operator,
                        "_run",
                        side_effect=[
                            _result(stdout=fragment + "\n"),
                            _result(stdout=_reconciliation(fragment=fragment)),
                            _result(stdout=action),
                        ],
                    ),
                    patch.object(
                        operator.uuid,
                        "uuid4",
                        return_value=types.SimpleNamespace(hex=str(index) * 32),
                    ),
                ):
                    operator.grabowski_user_service("demo.service", action)

                self.assertEqual(
                    resources.acquire_resources.call_args.args[1],
                    [
                        "service:user-systemd:demo.service",
                        f"path:{fragment}",
                    ],
                )
                self.assertNotIn(
                    "unit_file_config_root",
                    resources.acquire_resources.call_args.kwargs["metadata"],
                )
                self.assertNotIn(
                    config_key,
                    resources.acquire_resources.call_args.args[1],
                )

    def test_reconciliation_requests_empty_properties_explicitly(self) -> None:
        with patch.object(
            operator,
            "_run",
            return_value=_result(stdout=_reconciliation(fragment="")),
        ) as run:
            state = operator._user_systemd_reconciliation_state("demo.timer")

        self.assertEqual(state["Job"], "")
        self.assertEqual(state["FragmentPath"], "")
        argv = run.call_args.args[0]
        self.assertIn("--all", argv)
        self.assertEqual(
            run.call_args.kwargs["timeout_seconds"],
            operator._USER_SYSTEMD_RECONCILIATION_TIMEOUT_SECONDS,
        )

    def test_job_pending_normalizes_systemd_zero_sentinel(self) -> None:
        self.assertFalse(operator._user_systemd_job_pending(""))
        self.assertFalse(operator._user_systemd_job_pending("0"))
        self.assertFalse(
            operator._user_systemd_job_pending(
                "0 /org/freedesktop/systemd1/job/0"
            )
        )
        self.assertTrue(operator._user_systemd_job_pending("77"))
        self.assertTrue(
            operator._user_systemd_job_pending(
                "77 /org/freedesktop/systemd1/job/77"
            )
        )

    def test_zero_job_pre_action_dispatches_mutation(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        action_result = _result(stdout="started")
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment, job="0")),
                    action_result,
                ],
            ) as run,
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        self.assertIs(result, action_result)
        self.assertEqual(
            run.call_args_list[-1].args[0],
            ["systemctl", "--user", "restart", "demo.service"],
        )

    def test_non_service_unit_remains_mutable(self) -> None:
        fragment = "/home/alex/.config/systemd/user/restic-backup-1930.timer"
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    _result(stdout="started"),
                ],
            ) as run,
        ):
            result = operator.grabowski_user_service(
                "restic-backup-1930.timer", "start"
            )

        self.assertEqual(result["returncode"], 0)
        self.assertIn(
            "service:user-systemd:restic-backup-1930.timer",
            resources.acquire_resources.call_args.args[1],
        )
        self.assertEqual(
            run.call_args_list[-1].args[0],
            ["systemctl", "--user", "start", "restic-backup-1930.timer"],
        )

    def test_lease_budget_outlives_validation_action_and_termination(self) -> None:
        bounded_effect_window = (
            operator._USER_SYSTEMD_FRAGMENT_LOOKUP_TIMEOUT_SECONDS
            + operator._USER_SYSTEMD_MUTATION_TIMEOUT_SECONDS
            + int(operator.PROCESS_TERMINATION_GRACE_SECONDS * 3)
        )
        self.assertGreater(
            operator._USER_SYSTEMD_LEASE_TTL_SECONDS,
            bounded_effect_window,
        )

    def test_foreign_unit_lease_blocks_before_effect(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        resources.acquire_resources.side_effect = RuntimeError(
            "Resource is leased: service:user-systemd:demo.service"
        )
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                return_value=_result(stdout=fragment + "\n"),
            ) as run,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "service:user-systemd:demo.service"
            ):
                operator.grabowski_user_service("demo.service", "start")

        self.assertEqual(run.call_count, 1)
        resources.release_resources.assert_not_called()

    def test_pathless_unit_uses_unit_authority(self) -> None:
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout="\n"),
                    _result(stdout=_reconciliation(fragment="")),
                    _result(stdout="ok"),
                ],
            ),
        ):
            operator.grabowski_user_service("transient.target", "start")

        self.assertEqual(
            resources.acquire_resources.call_args.args[1],
            ["service:user-systemd:transient.target"],
        )
        resources.release_resources.assert_called_once()

    def test_existing_job_is_durably_fenced_before_effect_and_releases_lease(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment, job="77")),
                ],
            ) as run,
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        self.assertEqual(run.call_count, 2)
        self.assertTrue(result["outcome_unknown"])
        coordination = result["user_service_coordination"]
        self.assertEqual(coordination["status"], "preexisting_job_fenced")
        self.assertTrue(coordination["durable_fence_active"])
        self.assertEqual(coordination["reconciliation"]["Job"], "77")
        self.assertEqual(
            coordination["handoff"],
            "durable_fence_requires_terminal_systemd_readback",
        )
        resources.renew_resources.assert_not_called()
        resources.release_resources.assert_called_once()
        self.assertIsNotNone(resources._fence_state["active"])

    def test_fragment_path_drift_preserves_primary_error(self) -> None:
        resources = _fake_resources()
        first = "/home/alex/.config/systemd/user/demo.service"
        second = "/usr/lib/systemd/user/demo.service"
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=first + "\n"),
                    _result(stdout=_reconciliation(fragment=second)),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "FragmentPath changed"):
                operator.grabowski_user_service("demo.service", "stop")

        resources.release_resources.assert_called_once()

    def test_pre_action_failure_plus_release_failure_keeps_primary_diagnostic(self) -> None:
        resources = _fake_resources()
        resources.release_resources.side_effect = OSError("release failed")
        first = "/home/alex/.config/systemd/user/demo.service"
        second = "/usr/lib/systemd/user/demo.service"
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=first + "\n"),
                    _result(stdout=_reconciliation(fragment=second)),
                ],
            ),
        ):
            with self.assertRaises(RuntimeError) as caught:
                operator.grabowski_user_service("demo.service", "stop")

        message = str(caught.exception)
        self.assertIn("FragmentPath changed", message)
        self.assertIn("pre-effect coordination recovery is uncertain", message)
        self.assertIn("primary_error_class=RuntimeError", message)
        self.assertIn("release_error_class=OSError", message)
        self.assertIn("lease_owner_id=", message)
        self.assertIn("service:user-systemd:demo.service", message)

    def test_pre_action_readback_failure_clears_own_fence_before_release(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    OSError("pre-action readback"),
                ],
            ),
        ):
            with self.assertRaisesRegex(OSError, "pre-action readback"):
                operator.grabowski_user_service("demo.service", "restart")

        self.assertIsNone(resources._fence_state["active"])
        resources.clear_user_systemd_uncertainty_fence.assert_called_once()
        self.assertEqual(
            resources.clear_user_systemd_uncertainty_fence.call_args.kwargs[
                "outcome"
            ],
            "pre_effect_abort",
        )
        resources.release_resources.assert_called_once()

    def test_pre_action_clearance_failure_exposes_exact_fence_identity(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        resources.clear_user_systemd_uncertainty_fence.side_effect = OSError(
            "clear failed"
        )
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    OSError("pre-action readback"),
                ],
            ),
        ):
            with self.assertRaises(RuntimeError) as caught:
                operator.grabowski_user_service("demo.service", "restart")

        message = str(caught.exception)
        self.assertIn("pre-action readback", message)
        self.assertIn("pre-effect coordination recovery is uncertain", message)
        self.assertIn("fence_clearance_error_class=OSError", message)
        self.assertIn("uncertainty_fence_id=" + "f" * 32, message)
        self.assertIn("service:user-systemd:demo.service", message)
        resources.release_resources.assert_called_once()
        self.assertIsNotNone(resources._fence_state["active"])

    def test_dispatching_phase_failure_clears_fence_before_effect(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        original_update = resources.update_user_systemd_uncertainty_fence.side_effect

        def fail_dispatching(fence_id, *, phase):
            if phase == "dispatching":
                raise RuntimeError("dispatching journal failed")
            return original_update(fence_id, phase=phase)

        resources.update_user_systemd_uncertainty_fence.side_effect = fail_dispatching
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                ],
            ) as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "dispatching journal failed"):
                operator.grabowski_user_service("demo.service", "restart")

        self.assertEqual(run.call_count, 2)
        self.assertIsNone(resources._fence_state["active"])
        self.assertEqual(
            resources.clear_user_systemd_uncertainty_fence.call_args.kwargs[
                "outcome"
            ],
            "pre_effect_abort",
        )
        resources.release_resources.assert_called_once()

    def test_completed_action_preserves_result_when_release_is_uncertain(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        resources.release_resources.side_effect = OSError("release transport")
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    _result(stdout="started"),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        coordination = result["user_service_coordination"]
        self.assertEqual(
            coordination["status"], "lease_release_unknown_after_observed_action"
        )
        self.assertTrue(coordination["action_result_observed"])
        self.assertFalse(coordination["retry_allowed"])
        self.assertEqual(coordination["lease_release_state"], "unknown")
        self.assertIsNone(coordination["lease_retained"])
        self.assertEqual(coordination["release_error_class"], "OSError")
        self.assertEqual(
            coordination["recovery"]["release_tool"],
            "grabowski_resource_release",
        )

    def test_nonzero_action_result_reconciles_before_fence_clear(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        nonzero = _result(stdout="bus disconnected", returncode=1)
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    nonzero,
                    _result(stdout=_reconciliation(fragment=fragment)),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        self.assertEqual(result["returncode"], 1)
        resources.renew_resources.assert_called_once()
        resources.clear_user_systemd_uncertainty_fence.assert_called_once()
        self.assertEqual(
            resources.clear_user_systemd_uncertainty_fence.call_args.kwargs[
                "outcome"
            ],
            "terminal_readback",
        )
        coordination = result["user_service_coordination"]
        self.assertEqual(
            coordination["status"], "reconciled_after_transport_uncertainty"
        )
        self.assertFalse(coordination["durable_fence_active"])
        self.assertEqual(coordination["lease_release_state"], "released")

    def test_nonzero_action_pending_job_keeps_durable_fence(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(operator.time, "sleep"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    _result(returncode=1),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        self.assertTrue(result["outcome_unknown"])
        self.assertEqual(
            result["user_service_coordination"]["reconciliation"]["Job"], "1234"
        )
        self.assertIsNotNone(resources._fence_state["active"])
        resources.clear_user_systemd_uncertainty_fence.assert_not_called()

    def test_timeout_terminal_readback_releases_renewed_authority(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        timed_out = _result(stdout="timed out", timed_out=True)
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    timed_out,
                    _result(stdout=_reconciliation(fragment=fragment)),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        resources.renew_resources.assert_called_once()
        self.assertEqual(
            resources.renew_resources.call_args.kwargs["ttl_seconds"],
            operator._USER_SYSTEMD_RECONCILIATION_LEASE_TTL_SECONDS,
        )
        resources.release_resources.assert_called_once()
        coordination = result["user_service_coordination"]
        self.assertEqual(
            coordination["status"], "reconciled_after_transport_uncertainty"
        )
        self.assertEqual(coordination["lease_release_state"], "released")
        self.assertFalse(coordination["lease_retained"])
        self.assertFalse(coordination["requires_readback_before_next_attempt"])

    def test_timeout_pending_job_handoff_is_bounded_and_releases_authority(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(operator.time, "sleep") as sleep,
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    _result(timed_out=True),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "start")

        resources.renew_resources.assert_called_once()
        sleep.assert_called_once_with(operator._USER_SYSTEMD_RECONCILIATION_POLL_SECONDS)
        resources.release_resources.assert_called_once()
        self.assertTrue(result["outcome_unknown"])
        coordination = result["user_service_coordination"]
        self.assertEqual(coordination["status"], "outcome_unknown")
        self.assertFalse(coordination["retry_allowed"])
        self.assertTrue(coordination["requires_readback_before_next_attempt"])
        self.assertEqual(coordination["lease_release_state"], "released")
        self.assertFalse(coordination["lease_retained"])
        self.assertEqual(coordination["reconciliation"]["Job"], "1234")
        self.assertEqual(
            coordination["handoff"],
            "durable_fence_requires_terminal_systemd_readback",
        )

    def test_permanent_readback_failure_handoff_releases_authority(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(operator.time, "sleep"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    _result(timed_out=True),
                    _result(returncode=1),
                    _result(returncode=1),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "stop")

        coordination = result["user_service_coordination"]
        self.assertTrue(result["outcome_unknown"])
        self.assertIsNone(coordination["reconciliation"])
        self.assertEqual(coordination["reconciliation_error_class"], "RuntimeError")
        self.assertEqual(coordination["lease_release_state"], "released")
        self.assertFalse(coordination["retry_allowed"])

    def test_success_then_readback_failure_does_not_report_stale_state(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(operator.time, "sleep"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    _result(timed_out=True),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                    _result(returncode=1),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        coordination = result["user_service_coordination"]
        self.assertIsNone(coordination["reconciliation"])
        self.assertEqual(coordination["reconciliation_error_class"], "RuntimeError")

    def test_renewal_failure_stays_fail_closed(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        resources.renew_resources.side_effect = RuntimeError("renew failed")
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(operator.time, "sleep"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    _result(timed_out=True),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "start")

        coordination = result["user_service_coordination"]
        self.assertTrue(result["outcome_unknown"])
        self.assertFalse(coordination["retry_allowed"])
        self.assertTrue(coordination["requires_readback_before_next_attempt"])
        self.assertEqual(coordination["renewal_error_class"], "RuntimeError")
        self.assertEqual(coordination["lease_release_state"], "released")

    def test_transport_exception_terminal_readback_preserves_exception_when_release_succeeds(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    OSError("transport"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                ],
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "unit state was reconciled before coordination release"
            ):
                operator.grabowski_user_service("demo.service", "restart")

        resources.release_resources.assert_called_once()

    def test_transport_exception_terminal_readback_release_failure_returns_identity(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        resources.release_resources.side_effect = OSError("release")
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    OSError("transport"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        self.assertTrue(result["outcome_unknown"])
        coordination = result["user_service_coordination"]
        self.assertEqual(
            coordination["status"],
            "lease_release_unknown_after_reconciled_transport_failure",
        )
        self.assertFalse(coordination["action_result_observed"])
        self.assertFalse(coordination["retry_allowed"])
        self.assertTrue(coordination["requires_readback_before_next_attempt"])
        self.assertEqual(coordination["lease_release_state"], "unknown")
        self.assertIsNone(coordination["lease_retained"])
        self.assertEqual(coordination["reconciliation"]["Job"], "")
        self.assertEqual(coordination["action_error_class"], "OSError")
        self.assertEqual(coordination["release_error_class"], "OSError")
        self.assertIn("lease_owner_id", coordination)
        self.assertIn("service:user-systemd:demo.service", coordination["resource_keys"])
        self.assertEqual(
            coordination["recovery"]["inspect_tool"],
            "grabowski_resource_inspect",
        )

    def test_pending_handoff_release_failure_keeps_exact_recovery_identity(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        resources.release_resources.side_effect = OSError("release")
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(operator.time, "sleep"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    _result(timed_out=True),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "stop")

        coordination = result["user_service_coordination"]
        self.assertEqual(
            coordination["status"],
            "lease_release_unknown_after_outcome_unknown",
        )
        self.assertEqual(coordination["lease_release_state"], "unknown")
        self.assertIsNone(coordination["lease_retained"])
        self.assertTrue(coordination["release_required_after_terminal_readback"])
        self.assertIn("last_known_lease_expires_at_unix", coordination)
        self.assertEqual(
            coordination["recovery"]["release_tool"],
            "grabowski_resource_release",
        )

    def test_unreadable_fence_stays_blocked_when_manager_has_no_unit_job(self) -> None:
        resources = _fake_resources()
        service_key = "service:user-systemd:demo.service"
        resources._fence_state["active"] = {
            "fence_id": "f" * 32,
            "owner_id": "operator:user-systemd-recovery",
            "unit": "demo.service",
            "action": "restart",
            "phase": "outcome_unknown",
            "resource_keys": [service_key],
            "lease_snapshots": [],
            "cleared_at_unix": None,
        }
        with patch.object(
            operator,
            "_run",
            side_effect=[OSError("unit unreadable"), _result(stdout="")],
        ):
            prior = operator._user_systemd_reconcile_durable_uncertainty(
                resources, [service_key]
            )

        self.assertIsNotNone(prior)
        self.assertTrue(prior["blocked"])
        self.assertEqual(prior["reconciliation_error_class"], "OSError")
        self.assertFalse(prior["manager_job_readback"]["job_present"])
        self.assertIsNotNone(resources._fence_state["active"])
        resources.clear_user_systemd_uncertainty_fence.assert_not_called()

    def test_live_fence_lease_blocks_reconciliation_before_systemd_readback(self) -> None:
        resources = _fake_resources()
        service_key = "service:user-systemd:demo.service"
        resources._fence_state["active"] = {
            "fence_id": "f" * 32,
            "owner_id": "operator:user-systemd-live",
            "unit": "demo.service",
            "action": "restart",
            "phase": "dispatching",
            "resource_keys": [service_key],
            "lease_snapshots": [],
            "cleared_at_unix": None,
        }
        resources.inspect_resources.return_value = {
            service_key: {
                "resource_key": service_key,
                "owner_id": "operator:user-systemd-live",
            }
        }
        with patch.object(operator, "_run") as run:
            prior = operator._user_systemd_reconcile_durable_uncertainty(
                resources, [service_key]
            )

        self.assertIsNotNone(prior)
        self.assertTrue(prior["blocked"])
        self.assertEqual(prior["live_lease_resource_keys"], [service_key])
        self.assertEqual(prior["lease_readback_error_class"], None)
        run.assert_not_called()
        resources.clear_user_systemd_uncertainty_fence.assert_not_called()

    def test_unreadable_fence_stays_blocked_when_manager_lists_unit_job(self) -> None:
        resources = _fake_resources()
        service_key = "service:user-systemd:demo.service"
        resources._fence_state["active"] = {
            "fence_id": "f" * 32,
            "owner_id": "operator:user-systemd-recovery",
            "unit": "demo.service",
            "action": "restart",
            "phase": "outcome_unknown",
            "resource_keys": [service_key],
            "lease_snapshots": [],
            "cleared_at_unix": None,
        }
        with patch.object(
            operator,
            "_run",
            side_effect=[
                OSError("unit unreadable"),
                _result(stdout="1234 demo.service restart running\n"),
            ],
        ):
            prior = operator._user_systemd_reconcile_durable_uncertainty(
                resources, [service_key]
            )

        self.assertIsNotNone(prior)
        self.assertTrue(prior["blocked"])
        self.assertTrue(prior["manager_job_readback"]["job_present"])
        self.assertIsNotNone(resources._fence_state["active"])
        resources.clear_user_systemd_uncertainty_fence.assert_not_called()

    def test_mutation_requires_fully_qualified_unit_before_observation(self) -> None:
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(operator, "_run") as run,
        ):
            with self.assertRaisesRegex(ValueError, "fully qualified"):
                operator.grabowski_user_service("demo", "restart")

        run.assert_not_called()
        resources.user_systemd_uncertainty_status.assert_not_called()
        resources.acquire_resources.assert_not_called()

    def test_fragment_path_nonzero_is_rejected(self) -> None:
        with patch.object(
            operator,
            "_run",
            return_value=_result(returncode=1),
        ):
            with self.assertRaisesRegex(RuntimeError, "Unable to resolve FragmentPath"):
                operator._user_systemd_fragment_path("demo.service")

    def test_fragment_path_ambiguous_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "Ambiguous FragmentPath"):
            operator._normalize_user_systemd_fragment_path(
                "demo.service",
                "/one/demo.service\n/two/demo.service\n",
            )

    def test_fragment_path_relative_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "not absolute"):
            operator._normalize_user_systemd_fragment_path(
                "demo.service",
                "relative/demo.service\n",
            )

    def test_real_resource_layer_blocks_other_public_writer_on_same_unit(self) -> None:
        unit = "grabowski-job-coordination-test"
        systemd_unit = f"{unit}.service"
        key = f"service:user-systemd:{systemd_unit}"
        fragment = f"/home/alex/.config/systemd/user/{systemd_unit}"
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "resources.sqlite3"
            with patch.object(real_resources, "RESOURCE_DB", database):
                foreign = real_resources.acquire_resources(
                    "test:foreign-user-systemd-writer",
                    [key],
                    purpose="prove shared unit authority",
                    ttl_seconds=120,
                )
                try:
                    with (
                        patch.object(operator, "_require_operator_mutation"),
                        patch.object(
                            operator,
                            "_run",
                            return_value=_result(stdout=fragment + "\n"),
                        ) as run,
                    ):
                        with self.assertRaisesRegex(RuntimeError, key):
                            operator.grabowski_job_cancel(unit)
                    self.assertEqual(run.call_count, 1)
                finally:
                    real_resources.release_resources(
                        foreign["owner_id"],
                        [key],
                        expected_leases=foreign["leases"],
                    )

    def test_real_resource_fence_blocks_after_ordinary_lease_release(self) -> None:
        unit = "grabowski-durable-fence-test.service"
        service_key = f"service:user-systemd:{unit}"
        keys = [service_key]
        owner = "operator:user-systemd-durable-fence-test"
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "resources.sqlite3"
            with patch.object(real_resources, "RESOURCE_DB", database):
                lease = real_resources.acquire_resources(
                    owner,
                    keys,
                    purpose="prove durable user-systemd uncertainty",
                    ttl_seconds=120,
                    metadata={"unit": unit, "action": "restart"},
                )
                fence = real_resources.prepare_user_systemd_uncertainty_fence(
                    owner,
                    keys,
                    expected_leases=lease["leases"],
                    unit=unit,
                    action="restart",
                )
                real_resources.release_resources(
                    owner,
                    keys,
                    expected_leases=lease["leases"],
                )

                with self.assertRaises(real_resources.ResourceUncertaintyConflict):
                    real_resources.acquire_resources(
                        "operator:user-systemd-second-writer",
                        [service_key],
                        purpose="must remain blocked after ordinary lease release",
                        ttl_seconds=120,
                    )
                active = real_resources.user_systemd_uncertainty_status(keys)
                self.assertIsNotNone(active)
                self.assertEqual(active["fence_id"], fence["fence_id"])
                real_resources.clear_user_systemd_uncertainty_fence(
                    fence["fence_id"],
                    outcome="terminal_readback",
                    evidence_sha256="e" * 64,
                )
                replacement = real_resources.acquire_resources(
                    "operator:user-systemd-second-writer",
                    [service_key],
                    purpose="allowed only after terminal readback clearance",
                    ttl_seconds=120,
                )
                real_resources.release_resources(
                    replacement["owner_id"],
                    [service_key],
                    expected_leases=replacement["leases"],
                )

    def test_real_resource_fence_allows_disjoint_unit_and_second_fence(self) -> None:
        unit_a = "grabowski-durable-fence-a.service"
        unit_b = "grabowski-durable-fence-b.timer"
        key_a = f"service:user-systemd:{unit_a}"
        key_b = f"service:user-systemd:{unit_b}"
        owner_a = "operator:user-systemd-durable-fence-a"
        owner_b = "operator:user-systemd-durable-fence-b"
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "resources.sqlite3"
            with patch.object(real_resources, "RESOURCE_DB", database):
                lease_a = real_resources.acquire_resources(
                    owner_a,
                    [key_a],
                    purpose="prove per-unit durable uncertainty a",
                    ttl_seconds=120,
                    metadata={"unit": unit_a, "action": "restart"},
                )
                fence_a = real_resources.prepare_user_systemd_uncertainty_fence(
                    owner_a,
                    [key_a],
                    expected_leases=lease_a["leases"],
                    unit=unit_a,
                    action="restart",
                )
                real_resources.release_resources(
                    owner_a,
                    [key_a],
                    expected_leases=lease_a["leases"],
                )

                lease_b = real_resources.acquire_resources(
                    owner_b,
                    [key_b],
                    purpose="disjoint unit must remain independently mutable",
                    ttl_seconds=120,
                    metadata={"unit": unit_b, "action": "start"},
                )
                fence_b = real_resources.prepare_user_systemd_uncertainty_fence(
                    owner_b,
                    [key_b],
                    expected_leases=lease_b["leases"],
                    unit=unit_b,
                    action="start",
                )
                real_resources.release_resources(
                    owner_b,
                    [key_b],
                    expected_leases=lease_b["leases"],
                )

                active_a = real_resources.user_systemd_uncertainty_status([key_a])
                active_b = real_resources.user_systemd_uncertainty_status([key_b])
                self.assertIsNotNone(active_a)
                self.assertIsNotNone(active_b)
                self.assertEqual(active_a["fence_id"], fence_a["fence_id"])
                self.assertEqual(active_b["fence_id"], fence_b["fence_id"])
                with self.assertRaisesRegex(
                    RuntimeError,
                    "multiple active user-systemd uncertainty fences require exact resource keys",
                ):
                    real_resources.user_systemd_uncertainty_status()

                real_resources.clear_user_systemd_uncertainty_fence(
                    fence_a["fence_id"],
                    outcome="terminal_readback",
                    evidence_sha256="a" * 64,
                )
                real_resources.clear_user_systemd_uncertainty_fence(
                    fence_b["fence_id"],
                    outcome="terminal_readback",
                    evidence_sha256="b" * 64,
                )

    def test_real_resource_live_lease_prevents_fence_clearance_until_release(self) -> None:
        unit = "grabowski-live-fence-reconcile.service"
        service_key = f"service:user-systemd:{unit}"
        owner = "operator:user-systemd-live-fence-reconcile"
        reconciliation = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "UnitFileState": "enabled",
            "Job": "",
            "FragmentPath": "",
        }
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "resources.sqlite3"
            with patch.object(real_resources, "RESOURCE_DB", database):
                lease = real_resources.acquire_resources(
                    owner,
                    [service_key],
                    purpose="prove live lease blocks fence clearance",
                    ttl_seconds=120,
                    metadata={"unit": unit, "action": "restart"},
                )
                fence = real_resources.prepare_user_systemd_uncertainty_fence(
                    owner,
                    [service_key],
                    expected_leases=lease["leases"],
                    unit=unit,
                    action="restart",
                )
                with patch.object(
                    operator,
                    "_user_systemd_reconciliation_state",
                    return_value=reconciliation,
                ) as readback:
                    blocked = operator._user_systemd_reconcile_durable_uncertainty(
                        real_resources, [service_key]
                    )
                    self.assertTrue(blocked["blocked"])
                    self.assertEqual(
                        blocked["live_lease_resource_keys"], [service_key]
                    )
                    readback.assert_not_called()
                    self.assertIsNotNone(
                        real_resources.user_systemd_uncertainty_status([service_key])
                    )

                    real_resources.release_resources(
                        owner,
                        [service_key],
                        expected_leases=lease["leases"],
                    )
                    cleared = operator._user_systemd_reconcile_durable_uncertainty(
                        real_resources, [service_key]
                    )

                self.assertFalse(cleared["blocked"])
                self.assertEqual(cleared["fence"]["fence_id"], fence["fence_id"])
                self.assertIsNone(
                    real_resources.user_systemd_uncertainty_status([service_key])
                )

    def test_second_mutation_is_blocked_by_durable_pending_job_before_effect(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(operator.time, "sleep"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                    _result(timed_out=True),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                ],
            ),
        ):
            first = operator.grabowski_user_service("demo.service", "restart")

        self.assertTrue(first["outcome_unknown"])
        self.assertIsNotNone(resources._fence_state["active"])
        acquire_count = resources.acquire_resources.call_count

        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                return_value=_result(
                    stdout=_reconciliation(fragment=fragment, job="1234")
                ),
            ) as run,
        ):
            second = operator.grabowski_user_service("demo.service", "restart")

        self.assertTrue(second["outcome_unknown"])
        coordination = second["user_service_coordination"]
        self.assertEqual(
            coordination["status"],
            "blocked_by_durable_uncertainty_fence",
        )
        self.assertEqual(coordination["reconciliation"]["Job"], "1234")
        self.assertEqual(resources.acquire_resources.call_count, acquire_count)
        self.assertEqual(run.call_count, 1)
        self.assertIsNotNone(resources._fence_state["active"])

    def test_status_and_logs_remain_lease_free(self) -> None:
        resources = _fake_resources()
        with patch.dict(sys.modules, {"grabowski_resources": resources}):
            for action in ("status", "logs"):
                with self.subTest(action=action):
                    with (
                        patch.object(operator, "_require_operator_capability"),
                        patch.object(operator, "_require_operator_mutation") as mutation,
                        patch.object(operator, "_run", return_value=_result()) as run,
                    ):
                        operator.grabowski_user_service("demo.service", action)

                    mutation.assert_not_called()
                    self.assertEqual(run.call_count, 1)

        resources.acquire_resources.assert_not_called()
        resources.renew_resources.assert_not_called()
        resources.release_resources.assert_not_called()


if __name__ == "__main__":
    unittest.main()
