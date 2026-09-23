from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_operator as operator  # noqa: E402


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
            ]
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

    module.acquire_resources = MagicMock(side_effect=acquire)
    module.renew_resources = MagicMock(side_effect=renew)
    module.release_resources = MagicMock(
        return_value={
            "owner_id": "ignored",
            "force": False,
            "snapshot_guarded": True,
            "released": [],
        }
    )
    return module


class UserServiceCoordinationTests(unittest.TestCase):
    def test_mutation_acquires_unit_and_fragment_leases_before_systemctl(self) -> None:
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
                    _result(stdout=fragment + "\n"),
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
        owner = "operator:user-service-" + "1" * 32
        resource_keys = [
            "service:user-systemd:demo.service",
            f"path:{fragment}",
        ]
        resources.acquire_resources.assert_called_once_with(
            owner,
            resource_keys,
            purpose="user systemd restart demo.service",
            ttl_seconds=operator._USER_SERVICE_LEASE_TTL_SECONDS,
            metadata={"service": "demo.service", "action": "restart"},
        )
        self.assertEqual(
            run.call_args_list[-1],
            call(
                ["systemctl", "--user", "restart", "demo.service"],
                cwd=operator.HOME,
                timeout_seconds=operator._USER_SERVICE_MUTATION_TIMEOUT_SECONDS,
                max_output_bytes=operator.MAX_OUTPUT_BYTES,
            ),
        )
        resources.renew_resources.assert_not_called()
        resources.release_resources.assert_called_once()
        release_args = resources.release_resources.call_args
        self.assertEqual(release_args.args[:2], (owner, resource_keys))
        self.assertEqual(
            {item["resource_key"] for item in release_args.kwargs["expected_leases"]},
            set(resource_keys),
        )

    def test_lease_budget_outlives_validation_action_and_process_termination(self) -> None:
        bounded_effect_window = (
            operator._USER_SERVICE_FRAGMENT_LOOKUP_TIMEOUT_SECONDS
            + operator._USER_SERVICE_MUTATION_TIMEOUT_SECONDS
            + int(operator.PROCESS_TERMINATION_GRACE_SECONDS * 3)
        )
        self.assertGreater(operator._USER_SERVICE_LEASE_TTL_SECONDS, bounded_effect_window)

    def test_foreign_fragment_lease_blocks_before_service_effect(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        resources.acquire_resources.side_effect = RuntimeError("Resource is leased")
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
            with self.assertRaisesRegex(RuntimeError, "Resource is leased"):
                operator.grabowski_user_service("demo.service", "start")

        self.assertEqual(run.call_count, 1)
        resources.renew_resources.assert_not_called()
        resources.release_resources.assert_not_called()

    def test_fragment_path_drift_blocks_before_service_effect_and_releases(self) -> None:
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
                    _result(stdout=second + "\n"),
                ],
            ) as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "FragmentPath changed"):
                operator.grabowski_user_service("demo.service", "stop")

        self.assertEqual(run.call_count, 2)
        resources.renew_resources.assert_not_called()
        resources.release_resources.assert_called_once()

    def test_pathless_unit_uses_per_unit_coordination(self) -> None:
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
                    _result(stdout="\n"),
                    _result(stdout="ok"),
                ],
            ),
        ):
            operator.grabowski_user_service("transient.service", "start")

        self.assertEqual(
            resources.acquire_resources.call_args.args[1],
            ["service:user-systemd:transient.service"],
        )
        resources.release_resources.assert_called_once()

    def test_timeout_reconciles_before_releasing_renewed_leases(self) -> None:
        fragment = "/home/alex/.config/systemd/user/demo.service"
        resources = _fake_resources()
        timed_out = _result(timed_out=True)
        with (
            patch.dict(sys.modules, {"grabowski_resources": resources}),
            patch.object(operator, "_require_operator_capability"),
            patch.object(operator, "_require_operator_mutation"),
            patch.object(
                operator,
                "_run",
                side_effect=[
                    _result(stdout=fragment + "\n"),
                    _result(stdout=fragment + "\n"),
                    timed_out,
                    _result(stdout=_reconciliation(fragment=fragment)),
                ],
            ),
            patch.object(
                operator.uuid,
                "uuid4",
                return_value=types.SimpleNamespace(hex="2" * 32),
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "restart")

        owner = "operator:user-service-" + "2" * 32
        resource_keys = [
            "service:user-systemd:demo.service",
            f"path:{fragment}",
        ]
        resources.renew_resources.assert_called_once()
        renew_args = resources.renew_resources.call_args
        self.assertEqual(renew_args.args[:2], (owner, resource_keys))
        self.assertEqual(
            renew_args.kwargs["ttl_seconds"],
            operator._USER_SERVICE_UNCERTAIN_LEASE_TTL_SECONDS,
        )
        resources.release_resources.assert_called_once()
        released_snapshots = resources.release_resources.call_args.kwargs[
            "expected_leases"
        ]
        self.assertTrue(
            all(
                item["expires_at_unix"]
                == 200 + operator._USER_SERVICE_UNCERTAIN_LEASE_TTL_SECONDS
                for item in released_snapshots
            )
        )
        coordination = result["user_service_coordination"]
        self.assertEqual(
            coordination["status"], "reconciled_after_transport_uncertainty"
        )
        self.assertFalse(coordination["lease_retained"])
        self.assertFalse(coordination["requires_readback_before_next_attempt"])

    def test_timeout_with_pending_job_retains_renewed_leases(self) -> None:
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
                    _result(stdout=fragment + "\n"),
                    _result(timed_out=True),
                    _result(stdout=_reconciliation(fragment=fragment, job="1234")),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "start")

        resources.renew_resources.assert_called_once()
        resources.release_resources.assert_not_called()
        coordination = result["user_service_coordination"]
        self.assertEqual(coordination["status"], "outcome_unknown")
        self.assertTrue(coordination["lease_retained"])
        self.assertTrue(coordination["requires_readback_before_next_attempt"])
        self.assertTrue(coordination["release_required_after_terminal_readback"])
        self.assertEqual(coordination["reconciliation"]["Job"], "1234")

    def test_timeout_with_failed_readback_retains_renewed_leases(self) -> None:
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
                    _result(stdout=fragment + "\n"),
                    _result(timed_out=True),
                    _result(returncode=1),
                ],
            ),
        ):
            result = operator.grabowski_user_service("demo.service", "stop")

        resources.renew_resources.assert_called_once()
        resources.release_resources.assert_not_called()
        coordination = result["user_service_coordination"]
        self.assertEqual(coordination["status"], "outcome_unknown")
        self.assertTrue(coordination["lease_retained"])
        self.assertEqual(
            coordination["reconciliation_error_class"], "RuntimeError"
        )

    def test_transport_exception_reconciles_before_release_and_error(self) -> None:
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
                    _result(stdout=fragment + "\n"),
                    OSError("transport"),
                    _result(stdout=_reconciliation(fragment=fragment)),
                ],
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "unit state was reconciled before coordination release"
            ):
                operator.grabowski_user_service("demo.service", "restart")

        resources.renew_resources.assert_called_once()
        resources.release_resources.assert_called_once()

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
