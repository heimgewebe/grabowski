from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import deploy_runtime as core
import deploy_runtime_dual as dual


RUNTIME = Path("/home/alex/.local/share/grabowski-mcp")
CONTRACT = core.load_contract(ROOT / "config" / "runtime-entrypoint.json")


def observation(active: bool) -> core.ServiceObservation:
    return core.ServiceObservation(
        query_valid=True,
        load_state="loaded",
        active_state="active" if active else "inactive",
        sub_state="running" if active else "dead",
        main_pid=123 if active else 0,
        returncode=0,
    )


class ProfileTopologyTests(unittest.TestCase):
    def topology(self, payload):
        with mock.patch.object(dual, "_load_yaml", return_value=payload):
            return dual.profile_topology(Path("profile.yaml"), RUNTIME)

    def test_url_profile_without_command_is_accepted(self) -> None:
        result = self.topology(
            {"mcp": {"server_urls": [{"url": "http://127.0.0.1:18181/mcp"}]}}
        )
        self.assertEqual(result.kind, "url")
        self.assertEqual(result.server_url_count, 1)

    def test_legacy_command_profile_is_preserved(self) -> None:
        result = self.topology(
            {
                "command": [
                    str(RUNTIME / ".venv/bin/python"),
                    "-m",
                    CONTRACT.module,
                ]
            }
        )
        self.assertEqual(result.kind, "legacy-stdio")
        self.assertIsNotNone(result.legacy_entrypoint)

    def test_mixed_command_and_url_profile_is_rejected(self) -> None:
        payload = {
            "command": [
                str(RUNTIME / ".venv/bin/python"),
                "-m",
                CONTRACT.module,
            ],
            "mcp": {"server_urls": [{"url": "http://127.0.0.1:18181/mcp"}]},
        }
        with self.assertRaises(core.DeployError):
            self.topology(payload)

    def test_empty_or_wrongly_typed_server_urls_are_rejected(self) -> None:
        invalid = [
            {"mcp": {"server_urls": []}},
            {"mcp": {"server_urls": "http://127.0.0.1:18181/mcp"}},
            {"mcp": {"server_urls": [42]}},
            {"mcp": {"server_urls": [{}]}},
            {"mcp": {"server_urls": [{"url": ""}]}},
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(core.DeployError):
                    self.topology(payload)

    def test_multiple_commands_are_rejected(self) -> None:
        payload = {
            "outer": {
                "command": [
                    str(RUNTIME / ".venv/bin/python"),
                    "-m",
                    CONTRACT.module,
                ]
            },
            "other": {
                "command": [
                    str(RUNTIME / ".venv/bin/python"),
                    "-m",
                    CONTRACT.module,
                ]
            },
        }
        with self.assertRaises(core.DeployError):
            self.topology(payload)


class OperatorIdentityTests(unittest.TestCase):
    def test_expected_operator_argv_is_exact(self) -> None:
        self.assertEqual(
            dual.expected_operator_argv(RUNTIME, CONTRACT),
            [
                str(RUNTIME / ".venv/bin/python"),
                "-m",
                CONTRACT.module,
                "--transport",
                "streamable-http",
                "--host",
                "127.0.0.1",
                "--port",
                "18181",
            ],
        )

    def test_operator_process_accepts_only_exact_argv_and_python(self) -> None:
        expected = dual.expected_operator_argv(RUNTIME, CONTRACT)
        python_path = RUNTIME / ".venv/bin/python"
        with (
            mock.patch.object(dual, "_service_main_pid", return_value=456),
            mock.patch.object(core, "process_argv", return_value=expected),
            mock.patch.object(core, "process_exe", return_value=python_path),
            mock.patch.object(
                core,
                "verify_entrypoint_importable",
                return_value=Path("/release/grabowski_operator.py"),
            ),
            mock.patch.object(Path, "resolve", autospec=True, side_effect=lambda value: value),
        ):
            result = dual.verify_operator_process(RUNTIME, CONTRACT)
        self.assertEqual(result["pid"], 456)

    def test_wrong_host_port_or_module_is_rejected(self) -> None:
        expected = dual.expected_operator_argv(RUNTIME, CONTRACT)
        variants = [
            [*expected[:-3], "0.0.0.0", *expected[-2:]],
            [*expected[:-1], "9999"],
            [expected[0], "-m", "other_module", *expected[3:]],
        ]
        for argv in variants:
            with self.subTest(argv=argv):
                with (
                    mock.patch.object(dual, "_service_main_pid", return_value=456),
                    mock.patch.object(core, "process_argv", return_value=argv),
                ):
                    with self.assertRaises(core.DeployError):
                        dual.verify_operator_process(RUNTIME, CONTRACT)


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class OperatorListenerGateTests(unittest.TestCase):
    def test_listener_gate_waits_for_two_consecutive_successful_samples(self) -> None:
        with (
            mock.patch.object(
                dual.socket,
                "create_connection",
                side_effect=[
                    ConnectionRefusedError("refused"),
                    FakeSocket(),
                    ConnectionRefusedError("flapped"),
                    FakeSocket(),
                    FakeSocket(),
                ],
            ) as connect,
            mock.patch.object(dual.time, "sleep"),
        ):
            result = dual.require_operator_listener(timeout_seconds=1)
        self.assertEqual(result["successful_samples"], 2)
        self.assertEqual(result["attempts"], 5)
        self.assertEqual(connect.call_count, 5)

    def test_listener_gate_fails_closed_on_timeout(self) -> None:
        with (
            mock.patch.object(
                dual.socket,
                "create_connection",
                side_effect=ConnectionRefusedError("refused"),
            ),
            mock.patch.object(
                dual.time,
                "monotonic",
                side_effect=[0.0, 0.0, 0.0, 0.1, 0.1, 0.31],
            ),
            mock.patch.object(dual.time, "sleep"),
        ):
            with self.assertRaisesRegex(core.DeployError, "Operator-Listener"):
                dual.require_operator_listener(timeout_seconds=0.3)


class DeploymentSequenceTests(unittest.TestCase):
    def snapshot(self):
        return SimpleNamespace(
            contract=CONTRACT,
            repo_head="a" * 40,
            source_sha256="b" * 64,
            runtime_lock_sha256="c" * 64,
        )

    def build(self):
        return SimpleNamespace(
            release_path=Path("/release/new"),
            release_id="new",
            protocol_version="2025-06-18",
        )

    def test_url_preflight_requires_operator_listener(self) -> None:
        events: list[str] = []
        snapshot = self.snapshot()
        topology = dual.ProfileTopology("url", server_url_count=1)
        with (
            mock.patch.object(core, "snapshot_from_git", return_value=snapshot),
            mock.patch.object(core, "require_runtime_replaceable", return_value=RUNTIME),
            mock.patch.object(dual, "profile_topology", return_value=topology),
            mock.patch.object(dual, "require_topology_matches_contract"),
            mock.patch.object(
                dual,
                "require_service_active",
                side_effect=lambda unit: events.append(f"active:{unit}") or observation(True),
            ),
            mock.patch.object(
                dual,
                "verify_operator_process",
                side_effect=lambda *args, **kwargs: events.append("verify:operator") or {"pid": 1},
            ),
            mock.patch.object(
                dual,
                "require_operator_listener",
                side_effect=lambda **kwargs: events.append("listener") or {"successful_samples": 2},
            ),
            mock.patch.object(
                dual,
                "verify_tunnel_process",
                side_effect=lambda: events.append("verify:tunnel") or {"pid": 2},
            ),
        ):
            result = dual.preflight_url(ROOT, RUNTIME, Path("profile.yaml"))
        self.assertEqual(result, (snapshot, RUNTIME, topology))
        self.assertEqual(
            events,
            [
                f"active:{dual.OPERATOR_SERVICE}",
                f"active:{dual.TUNNEL_SERVICE}",
                "verify:operator",
                "listener",
                "verify:tunnel",
            ],
        )

    def test_cutover_order_is_tunnel_then_operator_and_reverse_on_start(self) -> None:
        events: list[str] = []
        active = observation(True)
        ready = dual.DualReadiness(True, active, active, "live", "ready")
        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(self.snapshot(), RUNTIME, dual.ProfileTopology("url", server_url_count=1)),
            ),
            mock.patch.object(core, "build_release", return_value=self.build()),
            mock.patch.object(core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(core, "verify_manifest"),
            mock.patch.object(core, "capture_pointer", return_value=SimpleNamespace()),
            mock.patch.object(
                dual,
                "stop_service",
                side_effect=lambda unit: events.append(f"stop:{unit}") or observation(False),
            ),
            mock.patch.object(
                dual,
                "start_service",
                side_effect=lambda unit: events.append(f"start:{unit}") or active,
            ),
            mock.patch.object(
                dual,
                "profile_topology",
                return_value=dual.ProfileTopology("url", server_url_count=1),
            ),
            mock.patch.object(dual, "require_topology_matches_contract"),
            mock.patch.object(
                core,
                "activate_pointer",
                side_effect=lambda activation: events.append("activate"),
            ),
            mock.patch.object(
                dual,
                "verify_operator_process",
                side_effect=lambda *args, **kwargs: events.append("verify:operator") or {"pid": 1},
            ),
            mock.patch.object(
                dual,
                "require_operator_listener",
                side_effect=lambda **kwargs: events.append("listener") or {"successful_samples": 2},
            ),
            mock.patch.object(
                dual,
                "verify_tunnel_process",
                side_effect=lambda: events.append("verify:tunnel") or {"pid": 2},
            ),
            mock.patch.object(dual, "wait_until_ready", return_value=ready),
            mock.patch.object(
                dual,
                "verify_url_runtime_identity",
                return_value={"process": {"pid": 1}},
            ),
        ):
            dual.deploy_url(ROOT, RUNTIME, Path("profile.yaml"), timeout_seconds=1)
        self.assertEqual(
            events,
            [
                f"stop:{dual.TUNNEL_SERVICE}",
                f"stop:{dual.OPERATOR_SERVICE}",
                "activate",
                f"start:{dual.OPERATOR_SERVICE}",
                "verify:operator",
                "listener",
                f"start:{dual.TUNNEL_SERVICE}",
                "verify:tunnel",
            ],
        )

    def test_operator_stop_failure_prevents_pointer_activation(self) -> None:
        events: list[str] = []

        def stop(unit: str):
            events.append(f"stop:{unit}")
            if unit == dual.OPERATOR_SERVICE:
                raise core.DeployError("operator stayed active")
            return observation(False)

        def rollback(*args, **kwargs):
            events.append("rollback")
            raise core.DeployError("rolled back")

        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(self.snapshot(), RUNTIME, dual.ProfileTopology("url", server_url_count=1)),
            ),
            mock.patch.object(core, "build_release", return_value=self.build()),
            mock.patch.object(core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(core, "verify_manifest"),
            mock.patch.object(core, "capture_pointer", return_value=SimpleNamespace()),
            mock.patch.object(dual, "stop_service", side_effect=stop),
            mock.patch.object(core, "activate_pointer") as activate,
            mock.patch.object(dual, "rollback_url", side_effect=rollback),
        ):
            with self.assertRaises(core.DeployError):
                dual.deploy_url(ROOT, RUNTIME, Path("profile.yaml"), timeout_seconds=1)
        activate.assert_not_called()
        self.assertEqual(
            events,
            [
                f"stop:{dual.TUNNEL_SERVICE}",
                f"stop:{dual.OPERATOR_SERVICE}",
                "rollback",
            ],
        )

    def test_rollback_stops_both_restores_then_starts_operator_before_tunnel(self) -> None:
        events: list[str] = []
        active = observation(True)
        inactive = observation(False)
        ready = dual.DualReadiness(True, active, active, "live", "ready")
        activation = SimpleNamespace(
            runtime=RUNTIME,
            previous=SimpleNamespace(),
        )
        with (
            mock.patch.object(
                dual,
                "stop_service",
                side_effect=lambda unit: events.append(f"stop:{unit}") or inactive,
            ),
            mock.patch.object(
                core,
                "restore_pointer",
                side_effect=lambda value: events.append("restore") or value,
            ),
            mock.patch.object(
                core,
                "verify_pointer_state",
                side_effect=lambda *args: events.append("verify:pointer") or SimpleNamespace(),
            ),
            mock.patch.object(
                dual,
                "start_service",
                side_effect=lambda unit: events.append(f"start:{unit}") or active,
            ),
            mock.patch.object(
                dual,
                "verify_operator_process",
                side_effect=lambda *args, **kwargs: events.append("verify:operator") or {"pid": 1},
            ),
            mock.patch.object(
                dual,
                "require_operator_listener",
                side_effect=lambda **kwargs: events.append("listener") or {"successful_samples": 2},
            ),
            mock.patch.object(dual, "wait_until_ready", return_value=ready),
        ):
            with self.assertRaises(core.DeployError):
                dual.rollback_url(
                    core.DeployError("primary"),
                    activation=activation,
                    contract=CONTRACT,
                    timeout_seconds=1,
                )
        self.assertEqual(
            events,
            [
                f"stop:{dual.TUNNEL_SERVICE}",
                f"stop:{dual.OPERATOR_SERVICE}",
                "restore",
                "verify:pointer",
                f"start:{dual.OPERATOR_SERVICE}",
                "verify:operator",
                "listener",
                f"start:{dual.TUNNEL_SERVICE}",
            ],
        )


if __name__ == "__main__":
    unittest.main()
