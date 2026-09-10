from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

ROOT = Path(__file__).resolve().parents[1]
for import_root in (ROOT / "src", ROOT / "tools"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

import deploy_kleiner_maulwurf as km


class KleinerMaulwurfDeployTests(unittest.TestCase):
    def _state(self) -> km.CutoverState:
        old_binding = {"release_id": "old-release", "repo_head": "a" * 40}
        new_binding = {"release_id": "new-release", "repo_head": "b" * 40}
        return km.CutoverState(
            repo=Path("/repo"),
            runtime=Path("/runtime"),
            release_path=Path("/release-new"),
            release_id="new-release",
            snapshot=SimpleNamespace(repo_head="b" * 40),
            activation=object(),
            old_release_path=Path("/release-old"),
            old_selector={
                "selector_sha256": "1" * 64,
                "selected_slot": "green",
                "upstream_port": km.MCP_PORT,
                "runtime_binding": old_binding,
                "runtime_binding_sha256": "2" * 64,
            },
            old_binding=old_binding,
            old_binding_sha256="2" * 64,
            new_binding=new_binding,
            new_binding_sha256="3" * 64,
            selector_path=Path("/selector.json"),
        )

    def test_stack_stop_and_start_order_is_dependency_safe(self) -> None:
        with (
            patch.object(km, "_systemctl") as systemctl,
            patch.object(km, "_wait_service"),
            patch.object(km, "_wait_port"),
        ):
            km._stop_stack(10)
            km._start_stack(10)

        self.assertEqual(
            systemctl.call_args_list,
            [
                call("stop", km.TUNNEL_SERVICE),
                call("stop", km.INGRESS_SERVICE),
                call("stop", km.MCP_SERVICE),
                call("start", km.MCP_SERVICE),
                call("start", km.INGRESS_SERVICE),
                call("start", km.TUNNEL_SERVICE),
            ],
        )

    def test_success_publishes_selector_before_ingress_and_tunnel_start(self) -> None:
        state = self._state()
        events: list[str] = []

        def systemctl(action: str, service: str) -> None:
            events.append(f"{action}:{service}")

        def wait_port(port: int, *, timeout_seconds: int) -> None:
            del timeout_seconds
            events.append(f"port:{port}")

        def publish(**kwargs):
            self.assertEqual(kwargs["runtime_binding"], state.new_binding)
            events.append("selector:new")
            return {
                "selector_sha256": "4" * 64,
                "runtime_binding_sha256": state.new_binding_sha256,
            }

        with (
            patch.object(km, "_verify_pre_cutover_preimage"),
            patch.object(km, "_systemctl", side_effect=systemctl),
            patch.object(km, "_wait_service"),
            patch.object(km, "_wait_port", side_effect=wait_port),
            patch.object(
                km.core,
                "activate_pointer",
                side_effect=lambda _state: events.append("activate"),
            ),
            patch.object(km.ingress, "publish_routing_selector", side_effect=publish),
            patch.object(
                km,
                "_verify_final",
                side_effect=lambda _state: events.append("verify")
                or {"selector_sha256": "4" * 64},
            ),
        ):
            result = km._run_cutover(state, timeout_seconds=10)

        self.assertTrue(result["ok"])
        self.assertEqual(state.published_selector_sha256, "4" * 64)
        self.assertEqual(
            events,
            [
                f"stop:{km.TUNNEL_SERVICE}",
                f"stop:{km.INGRESS_SERVICE}",
                f"stop:{km.MCP_SERVICE}",
                "activate",
                f"start:{km.MCP_SERVICE}",
                f"port:{km.MCP_PORT}",
                "selector:new",
                f"start:{km.INGRESS_SERVICE}",
                f"port:{km.INGRESS_PORT}",
                f"start:{km.TUNNEL_SERVICE}",
                "verify",
            ],
        )

    def test_failure_after_candidate_activation_restores_full_stack(self) -> None:
        state = self._state()
        events: list[str] = []
        failed_ingress = False

        def systemctl(action: str, service: str) -> None:
            events.append(f"{action}:{service}")

        def wait_port(port: int, *, timeout_seconds: int) -> None:
            nonlocal failed_ingress
            del timeout_seconds
            if port == km.INGRESS_PORT and not failed_ingress:
                failed_ingress = True
                raise km.KleinerMaulwurfDeployError("ingress probe failed")

        with (
            patch.object(km, "_verify_pre_cutover_preimage"),
            patch.object(km, "_systemctl", side_effect=systemctl),
            patch.object(km, "_wait_service"),
            patch.object(km, "_wait_port", side_effect=wait_port),
            patch.object(km.core, "activate_pointer"),
            patch.object(
                km.ingress,
                "publish_routing_selector",
                return_value={
                    "selector_sha256": "4" * 64,
                    "runtime_binding_sha256": state.new_binding_sha256,
                },
            ),
            patch.object(
                km,
                "_restore_pointer",
                side_effect=lambda _state: events.append("restore:pointer"),
            ) as restore,
            patch.object(
                km,
                "_restore_selector",
                side_effect=lambda _state: events.append("restore:selector"),
            ),
            patch.object(km, "_verify_rollback"),
        ):
            with self.assertRaisesRegex(
                km.KleinerMaulwurfDeployError,
                "previous runtime was restored",
            ):
                km._run_cutover(state, timeout_seconds=10)

        restore.assert_called_once_with(state)
        self.assertIn("restore:pointer", events)
        self.assertIn("restore:selector", events)
        rollback_start = events.index("restore:selector") + 1
        self.assertEqual(
            [event for event in events[rollback_start:] if event.startswith("start:")],
            [
                f"start:{km.MCP_SERVICE}",
                f"start:{km.INGRESS_SERVICE}",
                f"start:{km.TUNNEL_SERVICE}",
            ],
        )

    def test_pre_cutover_pointer_drift_is_rejected_before_selector_read(self) -> None:
        state = self._state()
        with (
            patch.object(km.core, "verify_apply_snapshot_unchanged"),
            patch.object(km, "_runtime_release", return_value=Path("/foreign")),
            patch.object(km.ingress, "read_routing_selector") as read_selector,
            patch.object(km, "_require_stack_active") as stack,
        ):
            with self.assertRaisesRegex(
                km.KleinerMaulwurfDeployError,
                "runtime pointer changed",
            ):
                km._verify_pre_cutover_preimage(state)
        read_selector.assert_not_called()
        stack.assert_not_called()

    def test_pre_cutover_selector_drift_is_rejected_before_service_stop(self) -> None:
        state = self._state()
        drifted = {**state.old_selector, "selector_sha256": "9" * 64}
        with (
            patch.object(km.core, "verify_apply_snapshot_unchanged"),
            patch.object(
                km, "_runtime_release", return_value=state.old_release_path
            ),
            patch.object(km.ingress, "read_routing_selector", return_value=drifted),
            patch.object(km, "_require_stack_active") as stack,
        ):
            with self.assertRaisesRegex(
                km.KleinerMaulwurfDeployError,
                "routing selector changed",
            ):
                km._verify_pre_cutover_preimage(state)
        stack.assert_not_called()

    def test_pre_cutover_failure_does_not_enter_rollback(self) -> None:
        state = self._state()
        with (
            patch.object(
                km,
                "_verify_pre_cutover_preimage",
                side_effect=km.KleinerMaulwurfDeployError("preimage drift"),
            ),
            patch.object(km, "_stop_stack") as stop,
            patch.object(km, "_restore_pointer") as restore_pointer,
            patch.object(km, "_restore_selector") as restore_selector,
        ):
            with self.assertRaisesRegex(
                km.KleinerMaulwurfDeployError,
                "preimage drift",
            ):
                km._run_cutover(state, timeout_seconds=10)
        stop.assert_not_called()
        restore_pointer.assert_not_called()
        restore_selector.assert_not_called()

    def test_foreign_pointer_is_not_overwritten_during_rollback(self) -> None:
        state = self._state()
        with (
            patch.object(km, "_runtime_release", return_value=Path("/foreign")),
            patch.object(km.core, "restore_pointer") as restore,
        ):
            with self.assertRaisesRegex(
                km.KleinerMaulwurfDeployError,
                "outside this cutover",
            ):
                km._restore_pointer(state)
        restore.assert_not_called()

    def test_foreign_selector_is_not_overwritten_during_rollback(self) -> None:
        state = self._state()
        state.published_selector_sha256 = "4" * 64
        foreign = {**state.old_selector, "selector_sha256": "9" * 64}
        with (
            patch.object(km.ingress, "read_routing_selector", return_value=foreign),
            patch.object(km.ingress, "publish_routing_selector") as publish,
        ):
            with self.assertRaisesRegex(
                km.KleinerMaulwurfDeployError,
                "outside this cutover",
            ):
                km._restore_selector(state)
        publish.assert_not_called()

    def test_prepare_rejects_head_drift_before_service_or_build_effects(self) -> None:
        runtime = Path("/runtime")
        snapshot = SimpleNamespace(repo_head="a" * 40)
        with (
            patch.object(km.core, "require_runtime_replaceable", return_value=runtime),
            patch.object(km.core, "snapshot_from_worktree", return_value=snapshot),
            patch.object(km, "_require_stack_active") as stack,
            patch.object(km.core, "build_release") as build,
        ):
            with self.assertRaisesRegex(
                km.KleinerMaulwurfDeployError,
                "source checkout head differs",
            ):
                km._prepare_deploy(
                    ROOT,
                    runtime,
                    "b" * 40,
                    Path("/selector.json"),
                )
        stack.assert_not_called()
        build.assert_not_called()

    def test_deploy_rejects_invalid_binding_inputs_before_prepare(self) -> None:
        with (
            patch.object(km, "_prepare_deploy") as prepare,
            patch.object(km.core, "deployment_lock") as deployment_lock,
        ):
            with self.assertRaisesRegex(
                km.KleinerMaulwurfDeployError,
                "timeout must be between",
            ):
                km.deploy(
                    repo=Path("/repo"),
                    runtime=Path("/runtime"),
                    expected_head="a" * 40,
                    selector_path=Path("/selector.json"),
                    timeout_seconds=0,
                )
            with self.assertRaisesRegex(
                km.KleinerMaulwurfDeployError,
                "expected head must be",
            ):
                km.deploy(
                    repo=Path("/repo"),
                    runtime=Path("/runtime"),
                    expected_head="not-a-head",
                    selector_path=Path("/selector.json"),
                    timeout_seconds=10,
                )
        prepare.assert_not_called()
        deployment_lock.assert_not_called()

    def test_deploy_reuses_core_deployment_lock(self) -> None:
        state = self._state()
        with (
            patch.object(km.core, "deployment_lock") as deployment_lock,
            patch.object(km, "_prepare_deploy", return_value=state),
            patch.object(km, "_run_cutover", return_value={"ok": True}) as cutover,
        ):
            result = km.deploy(
                repo=Path("/repo"),
                runtime=Path("/runtime"),
                expected_head="a" * 40,
                selector_path=Path("/selector.json"),
                timeout_seconds=10,
            )
        self.assertEqual(result, {"ok": True})
        deployment_lock.assert_called_once_with(km.core.DEFAULT_LOCK_FILE)
        cutover.assert_called_once_with(state, timeout_seconds=10)


if __name__ == "__main__":
    unittest.main()