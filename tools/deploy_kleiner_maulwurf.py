#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import deploy_runtime as core
import grabowski_transport_ingress as ingress

MCP_SERVICE = "kleiner-maulwurf-mcp.service"
INGRESS_SERVICE = "kleiner-maulwurf-transport-ingress.service"
TUNNEL_SERVICE = "tunnel-client-kleiner-maulwurf.service"
START_ORDER = (MCP_SERVICE, INGRESS_SERVICE, TUNNEL_SERVICE)
STOP_ORDER = tuple(reversed(START_ORDER))
MCP_PORT = 18182
INGRESS_PORT = 18180
CANONICAL_RUNTIME = Path.home() / ".local/share/grabowski-mcp"
CANONICAL_SELECTOR = ingress.DEFAULT_SELECTOR_FILE


class KleinerMaulwurfDeployError(RuntimeError):
    pass


@dataclass
class CutoverState:
    repo: Path
    runtime: Path
    release_path: Path
    release_id: str
    snapshot: Any
    activation: Any
    old_release_path: Path
    old_selector: dict[str, Any]
    old_binding: dict[str, str]
    old_binding_sha256: str
    new_binding: dict[str, str]
    new_binding_sha256: str
    selector_path: Path
    published_selector_sha256: str | None = None
    rollback_selector_sha256: str | None = None


def _fail(message: str) -> None:
    raise KleinerMaulwurfDeployError(message)


def _candidate_cutover_id(state: CutoverState) -> str:
    return f"km-deploy-{state.snapshot.repo_head[:12]}"


def _rollback_cutover_id(state: CutoverState) -> str:
    return f"km-rollback-{state.snapshot.repo_head[:12]}"


def _systemctl(action: str, service: str) -> None:
    try:
        subprocess.run(
            ["systemctl", "--user", action, service],
            check=True,
            text=True,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KleinerMaulwurfDeployError(
            f"{action} failed for {service}"
        ) from exc


def _service_active(service: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "--user", "is-active", "--quiet", service],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KleinerMaulwurfDeployError(
            f"service state unavailable for {service}"
        ) from exc
    return result.returncode == 0


def _wait_service(service: str, *, active: bool, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _service_active(service) is active:
            return
        time.sleep(0.2)
    expected = "active" if active else "inactive"
    _fail(f"{service} did not become {expected}")


def _wait_port(port: int, *, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    _fail(f"loopback port {port} did not become ready")


def _runtime_release(runtime: Path) -> Path:
    try:
        return runtime.resolve(strict=True)
    except OSError as exc:
        raise KleinerMaulwurfDeployError(
            "runtime pointer is unavailable"
        ) from exc


def _require_stack_active() -> None:
    inactive = [service for service in START_ORDER if not _service_active(service)]
    if inactive:
        _fail("service stack is not fully active: " + ", ".join(inactive))


def _stop_stack(timeout_seconds: int) -> None:
    for service in STOP_ORDER:
        _systemctl("stop", service)
        _wait_service(service, active=False, timeout_seconds=timeout_seconds)


def _start_service(service: str, timeout_seconds: int) -> None:
    _systemctl("start", service)
    _wait_service(service, active=True, timeout_seconds=timeout_seconds)


def _start_stack(timeout_seconds: int) -> None:
    _start_service(MCP_SERVICE, timeout_seconds)
    _wait_port(MCP_PORT, timeout_seconds=timeout_seconds)
    _start_service(INGRESS_SERVICE, timeout_seconds)
    _wait_port(INGRESS_PORT, timeout_seconds=timeout_seconds)
    _start_service(TUNNEL_SERVICE, timeout_seconds)


def _selector_matches(
    selector: dict[str, Any],
    *,
    binding: dict[str, str],
    binding_sha256: str,
    selected_slot: str,
) -> bool:
    return (
        selector.get("runtime_binding") == binding
        and selector.get("runtime_binding_sha256") == binding_sha256
        and selector.get("selected_slot") == selected_slot
        and selector.get("upstream_port") == MCP_PORT
    )


def _selector_is_own_candidate(
    state: CutoverState, selector: dict[str, Any]
) -> bool:
    return (
        _selector_matches(
            selector,
            binding=state.new_binding,
            binding_sha256=state.new_binding_sha256,
            selected_slot=state.old_selector["selected_slot"],
        )
        and selector.get("previous_selector_sha256")
        == state.old_selector["selector_sha256"]
        and selector.get("cutover_id") == _candidate_cutover_id(state)
    )


def _verify_pre_cutover_preimage(state: CutoverState) -> None:
    core.verify_apply_snapshot_unchanged(
        state.repo, state.snapshot, state.release_path
    )
    if _runtime_release(state.runtime) != state.old_release_path:
        _fail("runtime pointer changed while the candidate release was built")
    current_selector = ingress.read_routing_selector(state.selector_path)
    if current_selector.get("selector_sha256") != state.old_selector.get(
        "selector_sha256"
    ):
        _fail("routing selector changed while the candidate release was built")
    if not _selector_matches(
        current_selector,
        binding=state.old_binding,
        binding_sha256=state.old_binding_sha256,
        selected_slot=state.old_selector["selected_slot"],
    ):
        _fail("routing selector no longer matches the serving preimage")
    _require_stack_active()


def _verify_pointer_before_activation(state: CutoverState) -> None:
    if _runtime_release(state.runtime) != state.old_release_path:
        _fail("runtime pointer changed after service stop; refusing activation")


def _prepare_deploy(repo: Path, expected_head: str) -> CutoverState:
    repo = repo.expanduser().resolve(strict=True)
    runtime = core.require_runtime_replaceable(CANONICAL_RUNTIME)
    selector_path = CANONICAL_SELECTOR
    snapshot = core.snapshot_from_worktree(repo)
    if snapshot.repo_head != expected_head:
        _fail(
            "source checkout head differs from expected head: "
            f"{snapshot.repo_head} != {expected_head}"
        )

    _require_stack_active()
    old_pointer = core.capture_pointer(runtime)
    if old_pointer.kind != "symlink":
        _fail("smaller-mole runtime must already be an atomic symlink pointer")
    old_release_path = _runtime_release(runtime)
    old_binding, old_binding_sha256 = ingress._read_runtime_binding(
        old_release_path / "deployment-manifest.json"
    )
    old_selector = ingress.read_routing_selector(selector_path)
    if not _selector_matches(
        old_selector,
        binding=old_binding,
        binding_sha256=old_binding_sha256,
        selected_slot=old_selector["selected_slot"],
    ):
        _fail("routing selector does not match the currently serving runtime")

    build = core.build_release(snapshot, core.releases_root_for(runtime), runtime)
    core.verify_manifest(
        build.release_path,
        snapshot=snapshot,
        stable_runtime=runtime,
        expected_agent_instructions=build.agent_instructions,
    )
    new_binding, new_binding_sha256 = ingress._read_runtime_binding(
        build.release_path / "deployment-manifest.json"
    )
    core.verify_apply_snapshot_unchanged(repo, snapshot, build.release_path)

    activation = core.ActivationState(
        runtime=runtime,
        release_path=build.release_path,
        previous=old_pointer,
    )
    return CutoverState(
        repo=repo,
        runtime=runtime,
        release_path=build.release_path,
        release_id=build.release_id,
        snapshot=snapshot,
        activation=activation,
        old_release_path=old_release_path,
        old_selector=old_selector,
        old_binding=old_binding,
        old_binding_sha256=old_binding_sha256,
        new_binding=new_binding,
        new_binding_sha256=new_binding_sha256,
        selector_path=selector_path,
    )


def _restore_pointer(state: CutoverState) -> None:
    current = _runtime_release(state.runtime)
    if current == state.old_release_path:
        return
    if current != state.release_path:
        _fail("runtime pointer changed outside this cutover; refusing rollback")
    core.restore_pointer(state.activation)


def _restore_selector(state: CutoverState) -> None:
    current = ingress.read_routing_selector(state.selector_path)
    selected_slot = state.old_selector["selected_slot"]
    if _selector_matches(
        current,
        binding=state.old_binding,
        binding_sha256=state.old_binding_sha256,
        selected_slot=selected_slot,
    ) and current.get("selector_sha256") == state.old_selector.get(
        "selector_sha256"
    ):
        state.rollback_selector_sha256 = state.old_selector["selector_sha256"]
        return

    current_sha256 = current.get("selector_sha256")
    if state.published_selector_sha256 is None:
        if not _selector_is_own_candidate(state, current):
            _fail(
                "ambiguous routing selector publication is not owned by this cutover"
            )
        state.published_selector_sha256 = current_sha256
    elif current_sha256 != state.published_selector_sha256:
        _fail("routing selector changed outside this cutover; refusing rollback")

    restored = ingress.publish_routing_selector(
        path=state.selector_path,
        expected_selector_sha256=state.published_selector_sha256,
        selected_slot=selected_slot,
        runtime_binding=state.old_binding,
        cutover_id=_rollback_cutover_id(state),
    )
    restored_sha256 = restored.get("selector_sha256")
    if not isinstance(restored_sha256, str) or len(restored_sha256) != 64:
        _fail("routing selector rollback returned no exact selector identity")
    if not _selector_matches(
        restored,
        binding=state.old_binding,
        binding_sha256=state.old_binding_sha256,
        selected_slot=selected_slot,
    ):
        _fail("routing selector rollback did not bind the previous runtime")
    state.rollback_selector_sha256 = restored_sha256


def _verify_final(state: CutoverState) -> dict[str, Any]:
    if _runtime_release(state.runtime) != state.release_path:
        _fail("runtime pointer does not resolve to the candidate release")
    selector = ingress.read_routing_selector(state.selector_path)
    selected_slot = state.old_selector["selected_slot"]
    if state.published_selector_sha256 is None or selector.get(
        "selector_sha256"
    ) != state.published_selector_sha256:
        _fail("routing selector identity changed after candidate publication")
    if not _selector_matches(
        selector,
        binding=state.new_binding,
        binding_sha256=state.new_binding_sha256,
        selected_slot=selected_slot,
    ):
        _fail("routing selector does not resolve to the candidate runtime")
    _require_stack_active()
    _wait_port(MCP_PORT, timeout_seconds=5)
    _wait_port(INGRESS_PORT, timeout_seconds=5)
    return selector


def _verify_rollback(state: CutoverState) -> None:
    if _runtime_release(state.runtime) != state.old_release_path:
        _fail("rollback runtime pointer does not resolve to the previous release")
    selector = ingress.read_routing_selector(state.selector_path)
    selected_slot = state.old_selector["selected_slot"]
    expected_selector_sha256 = (
        state.rollback_selector_sha256 or state.old_selector["selector_sha256"]
    )
    if selector.get("selector_sha256") != expected_selector_sha256:
        _fail("rollback routing selector identity changed after restoration")
    if not _selector_matches(
        selector,
        binding=state.old_binding,
        binding_sha256=state.old_binding_sha256,
        selected_slot=selected_slot,
    ):
        _fail("rollback routing selector does not resolve to the previous runtime")
    _require_stack_active()


def _run_cutover(state: CutoverState, *, timeout_seconds: int) -> dict[str, Any]:
    # This check is deliberately outside the rollback block: failure here means
    # no cutover effect started, so recovery must not stop or rewrite anything.
    _verify_pre_cutover_preimage(state)
    try:
        _stop_stack(timeout_seconds)
        # Stopping three dependent units is intentionally bounded but not atomic.
        # Re-read the pointer at the last possible moment before overwriting it.
        _verify_pointer_before_activation(state)
        core.activate_pointer(state.activation)

        _start_service(MCP_SERVICE, timeout_seconds)
        _wait_port(MCP_PORT, timeout_seconds=timeout_seconds)

        published = ingress.publish_routing_selector(
            path=state.selector_path,
            expected_selector_sha256=state.old_selector["selector_sha256"],
            selected_slot=state.old_selector["selected_slot"],
            runtime_binding=state.new_binding,
            cutover_id=_candidate_cutover_id(state),
        )
        published_sha256 = published.get("selector_sha256")
        if not isinstance(published_sha256, str) or len(published_sha256) != 64:
            _fail("routing selector publication returned no exact selector identity")
        state.published_selector_sha256 = published_sha256
        if published.get("runtime_binding_sha256") != state.new_binding_sha256:
            _fail("routing selector publication did not bind the candidate runtime")

        _start_service(INGRESS_SERVICE, timeout_seconds)
        _wait_port(INGRESS_PORT, timeout_seconds=timeout_seconds)
        _start_service(TUNNEL_SERVICE, timeout_seconds)
        selector = _verify_final(state)
        return {
            "ok": True,
            "repo_head": state.snapshot.repo_head,
            "release_id": state.release_id,
            "selector_sha256": selector["selector_sha256"],
            "services": list(START_ORDER),
        }
    except BaseException as original:
        rollback_errors: list[str] = []
        for phase, operation in (
            ("stop", lambda: _stop_stack(timeout_seconds)),
            ("pointer", lambda: _restore_pointer(state)),
            ("selector", lambda: _restore_selector(state)),
            ("services", lambda: _start_stack(timeout_seconds)),
            ("verify", lambda: _verify_rollback(state)),
        ):
            try:
                operation()
            except BaseException as rollback_exc:
                rollback_errors.append(
                    f"{phase}:{type(rollback_exc).__name__}:{rollback_exc}"
                )
        if rollback_errors:
            raise KleinerMaulwurfDeployError(
                "smaller-mole cutover failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from original
        raise KleinerMaulwurfDeployError(
            "smaller-mole cutover failed; previous runtime was restored"
        ) from original


def deploy(
    *,
    repo: Path,
    expected_head: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    if timeout_seconds < 1 or timeout_seconds > 120:
        _fail("timeout must be between 1 and 120 seconds")
    if len(expected_head) != 40 or any(
        c not in "0123456789abcdef" for c in expected_head
    ):
        _fail("expected head must be an exact lowercase 40-character commit SHA")
    with core.deployment_lock(core.DEFAULT_LOCK_FILE):
        state = _prepare_deploy(repo, expected_head)
        return _run_cutover(state, timeout_seconds=timeout_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build and atomically activate the canonical smaller-mole Grabowski "
            "runtime, including MCP, ingress and tunnel lifecycle."
        )
    )
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Required explicit acknowledgement that the runtime will be cut over.",
    )
    args = parser.parse_args()
    if not args.apply:
        parser.error("--apply is required for the runtime cutover")
    result = deploy(
        repo=args.repo,
        expected_head=args.expected_head,
        timeout_seconds=args.timeout,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())