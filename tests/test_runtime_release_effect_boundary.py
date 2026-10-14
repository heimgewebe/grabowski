"""Fail-closed effect-time release admission tests for central deploy entrypoints.

These cases use synthetic ingress readbacks only as negative test fixtures.
They do not produce, forge, or accept any independent R3/Captain authorization.
"""
from __future__ import annotations

import argparse
import os
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
import deploy_runtime_dual as dual  # noqa: E402


SERVING = "a" * 40
TARGET = "b" * 40
SOURCE = "c" * 64


def routing(head: str) -> dict:
    selector = {
        "selector_sha256": "2" * 64,
        "generation": 2,
        "selected_slot": "canonical",
        "upstream_port": 18181,
        "runtime_binding_sha256": "1" * 64,
        "repo_head": head,
        "release_id": "serving-release",
    }
    ingress = {
        "selector_sha256": selector["selector_sha256"],
        "selector_generation": selector["generation"],
        "selected_slot": selector["selected_slot"],
        "upstream_port": selector["upstream_port"],
        "runtime_binding_sha256": selector["runtime_binding_sha256"],
        "repo_head": selector["repo_head"],
        "release_id": selector["release_id"],
    }
    material = {"authoritative": True, "selector": selector, "ingress": ingress}
    return {**material, "readback_sha256": dual._json_sha256(material)}


class EffectTimeCentralAdmissionTests(unittest.TestCase):
    def test_blue_green_rechecks_under_lock_before_prepare(self):
        events = []

        @contextmanager
        def fake_lock(_path):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        def observe():
            events.append("trusted-readback")
            return routing(SERVING)

        def prepare(*_args, **_kwargs):
            events.append("prepare-green")
            raise AssertionError("source-changing green must never be prepared")

        def persist(receipt):
            return {"path": "/synthetic/failure", "receipt_sha256": receipt["receipt_sha256"]}

        with (
            patch.object(dual.core, "deployment_lock", side_effect=fake_lock),
            patch.object(dual, "observe_authoritative_routing", side_effect=observe),
            patch.object(dual, "prepare_production_blue_green_runtime", side_effect=prepare),
            patch.object(dual, "_persist_production_blue_green_receipt", side_effect=persist),
        ):
            result = dual.run_production_blue_green_cutover(
                repo=Path("/synthetic"),
                expected_head=TARGET,
                source_identity_sha256=SOURCE,
                cutover_id="synthetic-central-release-gate",
            )
        self.assertEqual("failed_pre_cutover", result["outcome"])
        self.assertIn("lock-enter", events)
        self.assertIn("trusted-readback", events)
        self.assertLess(events.index("lock-enter"), events.index("trusted-readback"))
        self.assertNotIn("prepare-green", events)
        self.assertEqual("lock-exit", events[-1])

    def test_serving_changes_while_lock_is_contended_blocks_previous_preview(self):
        """A correct preview cannot authorize a stale post-lock productive effect."""
        state = {"head": SERVING}
        events = []

        @contextmanager
        def switch_during_lock(_path):
            events.append("lock-enter")
            state["head"] = TARGET
            try:
                yield
            finally:
                events.append("lock-exit")

        def readback():
            events.append("effect-time-readback")
            return routing(state["head"])

        with (
            patch.object(dual.core, "deployment_lock", side_effect=switch_during_lock),
            patch.object(dual, "observe_authoritative_routing", side_effect=readback),
            patch.object(dual, "prepare_production_blue_green_runtime") as effect,
            patch.object(
                dual, "_persist_production_blue_green_receipt",
                side_effect=lambda receipt: {
                    "path": "/synthetic/preflight",
                    "receipt_sha256": receipt["receipt_sha256"],
                },
            ),
        ):
            # Preview is correct before another deployment obtains the lock.
            self.assertEqual(SERVING, dual.observe_authoritative_routing()["ingress"]["repo_head"])
            result = dual.run_production_blue_green_cutover(
                repo=Path("/synthetic"),
                expected_head=SERVING,
                source_identity_sha256=SOURCE,
                cutover_id="stale-preview-denied-under-lock",
            )
        self.assertEqual("failed_pre_cutover", result["outcome"])
        effect.assert_not_called()
        self.assertEqual(
            ["effect-time-readback", "lock-enter", "effect-time-readback", "lock-exit"],
            events,
        )

    def test_valid_sha256_git_head_unchanged_serving_is_not_misclassified(self):
        head = "a" * 64
        with patch.object(dual, "observe_authoritative_routing", return_value=routing(head)):
            admitted = dual.require_locked_release_source_admission(expected_head=head)
        self.assertEqual("already-serving-exact-source", admitted["status"])
        self.assertEqual(head, admitted["serving_repo_head"])

    def test_direct_cli_apply_rejects_source_change_under_lock(self):
        events = []

        @contextmanager
        def fake_lock(_path):
            events.append("lock-enter")
            try:
                yield
            finally:
                events.append("lock-exit")

        def observe():
            events.append("trusted-readback")
            return routing(SERVING)

        args = argparse.Namespace(
            repo=Path("/synthetic"),
            runtime=Path("/synthetic/runtime"),
            profile_path=Path("/synthetic/profile"),
            lock_file=dual.core.DEFAULT_LOCK_FILE,
            timeout=1,
            expected_head=TARGET,
            bootstrap_recovery=False,
            check=False,
            preflight=False,
            apply=True,
        )
        with (
            patch.object(dual, "parse_args", return_value=args),
            patch.object(dual.core, "deployment_lock", side_effect=fake_lock),
            patch.object(dual, "preflight_url", return_value=(
                SimpleNamespace(repo_head=TARGET), None, None,
            )),
            patch.object(dual, "observe_authoritative_routing", side_effect=observe),
            patch.object(dual, "deploy_url") as effect,
        ):
            result = dual.main()
        self.assertEqual(1, result)
        self.assertIn("lock-enter", events)
        self.assertIn("trusted-readback", events)
        self.assertLess(events.index("lock-enter"), events.index("trusted-readback"))
        self.assertNotIn("deploy", events)
        effect.assert_not_called()

    def test_direct_cli_apply_requires_exact_expected_head(self):
        args = argparse.Namespace(
            repo=Path("/synthetic"),
            runtime=Path("/synthetic/runtime"),
            profile_path=Path("/synthetic/profile"),
            lock_file=dual.core.DEFAULT_LOCK_FILE,
            timeout=1,
            expected_head=None,
            bootstrap_recovery=False,
            check=False,
            preflight=False,
            apply=True,
        )
        with (
            patch.object(dual, "parse_args", return_value=args),
            patch.object(dual, "preflight_url") as preflight,
            patch.object(dual, "deploy_url") as effect,
        ):
            result = dual.main()
        self.assertEqual(1, result)
        preflight.assert_not_called()
        effect.assert_not_called()

    def test_productive_blue_green_refuses_noncanonical_lock_file(self):
        with patch.object(dual, "prepare_production_blue_green_runtime") as effect:
            with self.assertRaisesRegex(RuntimeError, "canonical deployment lock"):
                dual.run_production_blue_green_cutover(
                    repo=Path("/synthetic"),
                    expected_head=SERVING,
                    source_identity_sha256=SOURCE,
                    lock_file=Path("/synthetic/uncoordinated.lock"),
                )
            effect.assert_not_called()

    def test_direct_apply_refuses_noncanonical_lock_file(self):
        args = argparse.Namespace(
            repo=Path("/synthetic"),
            runtime=Path("/synthetic/runtime"),
            profile_path=Path("/synthetic/profile"),
            lock_file=Path("/synthetic/uncoordinated.lock"),
            timeout=1,
            expected_head=SERVING,
            bootstrap_recovery=False,
            check=False,
            preflight=False,
            apply=True,
        )
        with (
            patch.object(dual, "parse_args", return_value=args),
            patch.object(dual, "preflight_url") as preflight,
            patch.object(dual.core, "deployment_lock") as lock,
            patch.object(dual, "deploy_url") as effect,
        ):
            self.assertEqual(1, dual.main())
        preflight.assert_not_called()
        lock.assert_not_called()
        effect.assert_not_called()

    def test_direct_bootstrap_flag_requires_protected_system_origin(self):
        """Arbitrary CLI --bootstrap-recovery cannot bypass the locked release gate."""
        args = argparse.Namespace(
            repo=Path("/synthetic"), runtime=Path("/synthetic/runtime"),
            profile_path=Path("/synthetic/profile"),
            lock_file=dual.core.DEFAULT_LOCK_FILE, timeout=1,
            expected_head=TARGET, bootstrap_recovery=True,
            check=False, preflight=False, apply=True,
        )
        with (
            patch.object(dual, "parse_args", return_value=args),
            patch.object(dual.core, "deployment_lock") as lock,
            patch.object(dual, "deploy_url") as effect,
            patch.object(dual, "preflight_bootstrap_recovery_url") as preflight,
        ):
            self.assertEqual(1, dual.main())
        lock.assert_not_called()
        effect.assert_not_called()
        preflight.assert_not_called()

    def test_direct_bootstrap_function_requires_protected_system_origin(self):
        """Callable deploy_url(...bootstrap_recovery=True) is an effect entrypoint."""
        with patch.object(dual, "preflight_bootstrap_recovery_url") as preflight:
            with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                dual.deploy_url(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), timeout_seconds=1,
                    expected_head=TARGET, bootstrap_recovery=True,
                )
        preflight.assert_not_called()

    def test_rootbroker_bootstrap_cgroup_requires_exact_system_unit_and_uid(self):
        """The kernel system-cgroup, exact parent argv and root helper must agree."""
        nonce = "3" * 24
        trusted = (
            f"0::/system.slice/grabowski-runtime-bootstrap-"
            f"{TARGET[:12]}-{nonce}.service\n"
        )
        parent = (
            "/usr/bin/python3", str(dual.ROOT_BOOTSTRAP_HELPER),
            "user-execute", "--expected-head", TARGET,
            "--execution-id", nonce,
        )
        rejected_cgroups = (
            trusted.replace("/system.slice/", "/user.slice/"),
            trusted.replace(TARGET[:12], SERVING[:12]),
            trusted.replace("-" + nonce + ".service", "-bad.service"),
            trusted + "0::/user.slice/foreign.service\n",
            "",
        )
        # All positive evidence below is synthetic: these mocks can never
        # create an issuer, protected cgroup, Captain or real release permit.
        with (
            patch.object(dual.os, "getuid", return_value=1000),
            patch.object(dual.os, "geteuid", return_value=1000),
            patch.object(dual.os, "getgid", return_value=1000),
            patch.object(dual.os, "getegid", return_value=1000),
            patch.object(dual, "_bootstrap_recovery_parent_argv", return_value=parent),
            patch.object(
                dual, "_bootstrap_recovery_parent_executable",
                return_value="/usr/bin/python3.10",
            ),
            patch.object(dual, "_root_bootstrap_helper_owned", return_value=True),
            patch.object(dual, "_require_rootbroker_systemd_mainpid"),
        ):
            with (
                patch.object(dual, "_bootstrap_recovery_cgroup", return_value=trusted),
                patch.object(dual, "_bootstrap_recovery_parent_cgroup", return_value=trusted),
            ):
                self.assertIsNone(
                    dual.require_root_broker_bootstrap_origin(expected_head=TARGET)
                )
                with patch.object(dual.os, "geteuid", return_value=0):
                    with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                        dual.require_root_broker_bootstrap_origin(expected_head=TARGET)
                with patch.object(dual, "_root_bootstrap_helper_owned", return_value=False):
                    with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                        dual.require_root_broker_bootstrap_origin(expected_head=TARGET)
                with patch.object(
                    dual, "_bootstrap_recovery_parent_executable",
                    return_value="/home/alex/.local/bin/python3",
                ):
                    with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                        dual.require_root_broker_bootstrap_origin(expected_head=TARGET)
                wrong_parents = (
                    (*parent[:4], TARGET[:12] + "f" * 28, *parent[5:]),
                    (*parent[:-1], "4" * 24),
                    parent + ("--unauthorized-extra",),
                    ("/usr/bin/python3", "/tmp/mutable-helper", *parent[2:]),
                )
                for wrong in wrong_parents:
                    with self.subTest(parent=wrong):
                        with patch.object(
                            dual, "_bootstrap_recovery_parent_argv", return_value=wrong,
                        ):
                            with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                                dual.require_root_broker_bootstrap_origin(
                                    expected_head=TARGET
                                )
            for untrusted in rejected_cgroups:
                with self.subTest(cgroup=untrusted):
                    with (
                        patch.object(dual, "_bootstrap_recovery_cgroup", return_value=untrusted),
                        patch.object(dual, "_bootstrap_recovery_parent_cgroup", return_value=untrusted),
                    ):
                        with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                            dual.require_root_broker_bootstrap_origin(
                                expected_head=TARGET
                            )
            with (
                patch.object(dual, "_bootstrap_recovery_cgroup", return_value=trusted),
                patch.object(dual, "_bootstrap_recovery_parent_cgroup", return_value="/user.slice/other\n"),
            ):
                with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                    dual.require_root_broker_bootstrap_origin(expected_head=TARGET)

    def test_bootstrap_origin_rejects_forged_parent_inside_real_system_cgroup(self):
        """Same-UID argv inside an authentic unit is not systemd MainPID proof."""
        nonce = "3" * 24
        unit = f"grabowski-runtime-bootstrap-{TARGET[:12]}-{nonce}.service"
        group = f"/system.slice/{unit}"
        cgroup = f"0::{group}\n"
        parent_pid = 4242
        parent = (
            "/usr/bin/python3", str(dual.ROOT_BOOTSTRAP_HELPER),
            "user-execute", "--expected-head", TARGET,
            "--execution-id", nonce,
        )
        correct = {
            "Id": unit, "LoadState": "loaded", "ActiveState": "active",
            "Transient": "yes", "Type": "exec",
            "MainPID": str(parent_pid), "ControlGroup": group,
        }
        cases = {
            "other-main-pid": {"MainPID": "4243"},
            "not-transient": {"Transient": "no"},
            "inactive": {"ActiveState": "inactive"},
            "other-cgroup": {"ControlGroup": "/user.slice/other"},
            "other-unit": {"Id": "other.service"},
            "other-unit-type": {"Type": "simple"},
            "missing-main-pid": {"MainPID": ""},
        }
        with (
            patch.object(dual.os, "getuid", return_value=1000),
            patch.object(dual.os, "geteuid", return_value=1000),
            patch.object(dual.os, "getgid", return_value=1000),
            patch.object(dual.os, "getegid", return_value=1000),
            patch.object(dual.os, "getppid", return_value=parent_pid),
            patch.object(dual, "_root_bootstrap_helper_owned", return_value=True),
            patch.object(dual, "_bootstrap_recovery_cgroup", return_value=cgroup),
            patch.object(dual, "_bootstrap_recovery_parent_cgroup", return_value=cgroup),
            patch.object(dual, "_bootstrap_recovery_parent_executable", return_value="/usr/bin/python3.10"),
            patch.object(dual, "_bootstrap_recovery_parent_argv", return_value=parent),
        ):
            for label, changed in cases.items():
                observed = {**correct, **changed}
                payload = "".join(f"{key}={value}\n" for key, value in observed.items())
                with self.subTest(case=label):
                    with patch.object(
                        dual.core, "run",
                        return_value=SimpleNamespace(returncode=0, stdout=payload),
                    ) as show:
                        with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                            dual.require_root_broker_bootstrap_origin(expected_head=TARGET)
                    show.assert_called_once()
            valid_payload = "".join(f"{key}={value}\n" for key, value in correct.items())
            with patch.object(
                dual.core, "run",
                return_value=SimpleNamespace(returncode=0, stdout=valid_payload),
            ) as show:
                self.assertIsNone(
                    dual.require_root_broker_bootstrap_origin(expected_head=TARGET)
                )
            show.assert_called_once()
            self.assertEqual(
                {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                show.call_args.kwargs.get("env"),
                "systemd manager authentication must not inherit same-UID DBus environment",
            )
            with patch.object(
                dual.core, "run", return_value=SimpleNamespace(returncode=1, stdout=""),
            ):
                with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                    dual.require_root_broker_bootstrap_origin(expected_head=TARGET)

    def test_rootbroker_bootstrap_sha256_head_requires_full_parent_binding(self):
        """A 64-hex source cannot be exchanged for another with its prefix."""
        head, nonce = "c" * 64, "4" * 24
        cgroup = (
            "0::/system.slice/grabowski-runtime-bootstrap-"
            + head[:12] + "-" + nonce + ".service\n"
        )
        parent = (
            "/usr/bin/python3", str(dual.ROOT_BOOTSTRAP_HELPER),
            "user-execute", "--expected-head", head,
            "--execution-id", nonce,
        )
        with (
            patch.object(dual.os, "getuid", return_value=1000),
            patch.object(dual.os, "geteuid", return_value=1000),
            patch.object(dual.os, "getgid", return_value=1000),
            patch.object(dual.os, "getegid", return_value=1000),
            patch.object(dual, "_root_bootstrap_helper_owned", return_value=True),
            patch.object(dual, "_require_rootbroker_systemd_mainpid"),
            patch.object(dual, "_bootstrap_recovery_cgroup", return_value=cgroup),
            patch.object(dual, "_bootstrap_recovery_parent_cgroup", return_value=cgroup),
            patch.object(
                dual, "_bootstrap_recovery_parent_executable",
                return_value="/usr/bin/python3.10",
            ),
            patch.object(dual, "_bootstrap_recovery_parent_argv", return_value=parent),
        ):
            self.assertIsNone(
                dual.require_root_broker_bootstrap_origin(expected_head=head)
            )
            with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                dual.require_root_broker_bootstrap_origin(
                    expected_head=head[:12] + "d" * 52
                )
            wrong_parent = (
                *parent[:4], head[:12] + "d" * 52, *parent[5:],
            )
            with patch.object(
                dual, "_bootstrap_recovery_parent_argv", return_value=wrong_parent,
            ):
                with self.assertRaisesRegex(dual.core.DeployError, "bootstrap.*origin"):
                    dual.require_root_broker_bootstrap_origin(expected_head=head)

    def test_kernel_fd_lock_context_cannot_be_claimed_outside_exact_lock(self):
        """Actual temp flock readback: not a Captain/R3 grant or production lock."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "deploy.lock"
            other = root / "other.lock"
            with patch.object(dual.core, "DEFAULT_LOCK_FILE", target):
                with self.assertRaisesRegex(dual.core.DeployError, "canonical deployment lock"):
                    dual.core.require_canonical_deployment_lock_held()
                # Negative fixture: a manually invented ContextVar entry and a
                # real inode/FD do NOT establish kernel flock ownership.
                fd = os.open(target, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
                try:
                    info = os.fstat(fd)
                    token = dual.core._ACTIVE_DEPLOYMENT_LOCK.set((
                        os.getpid(), fd, info.st_dev, info.st_ino, str(target),
                    ))
                    try:
                        with self.assertRaisesRegex(
                            dual.core.DeployError, "canonical deployment lock"
                        ):
                            dual.core.require_canonical_deployment_lock_held()
                    finally:
                        dual.core._ACTIVE_DEPLOYMENT_LOCK.reset(token)
                finally:
                    os.close(fd)
                with dual.core.deployment_lock(other, state_root=root):
                    with self.assertRaisesRegex(dual.core.DeployError, "canonical deployment lock"):
                        dual.core.require_canonical_deployment_lock_held()
                with dual.core.deployment_lock(target, state_root=root):
                    self.assertIsNone(dual.core.require_canonical_deployment_lock_held())
                with self.assertRaisesRegex(dual.core.DeployError, "canonical deployment lock"):
                    dual.core.require_canonical_deployment_lock_held()

    def test_core_direct_same_source_without_lock_has_no_effect(self):
        """Even an already-serving commit needs the canonical effect-time lock."""
        with (
            patch.object(dual, "observe_authoritative_routing", return_value=routing(SERVING)),
            patch.object(dual.core, "snapshot_from_git") as snapshot,
            patch.object(dual.core, "build_release") as build,
        ):
            with self.assertRaisesRegex(dual.core.DeployError, "canonical deployment lock"):
                dual.core.deploy(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), timeout_seconds=1,
                    expected_head=SERVING,
                )
        snapshot.assert_not_called()
        build.assert_not_called()

    def test_dual_direct_same_source_without_lock_has_no_effect(self):
        with (
            patch.object(dual, "observe_authoritative_routing", return_value=routing(SERVING)),
            patch.object(dual, "preflight_url") as preflight,
            patch.object(dual.core, "build_release") as build,
        ):
            with self.assertRaisesRegex(dual.core.DeployError, "canonical deployment lock"):
                dual.deploy_url(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), timeout_seconds=1,
                    expected_head=SERVING,
                )
        preflight.assert_not_called()
        build.assert_not_called()

    def test_direct_green_prepare_without_lock_has_no_effect(self):
        with (
            patch.object(dual, "preflight_url") as preflight,
            patch.object(dual.core, "build_release") as build,
        ):
            with self.assertRaisesRegex(dual.core.DeployError, "canonical deployment lock"):
                dual.prepare_production_blue_green_runtime(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), timeout_seconds=1,
                    expected_head=SERVING, cutover_id="direct-outside-lock",
                )
        preflight.assert_not_called()
        build.assert_not_called()

    def test_core_direct_valid_but_nonserving_head_rejected_before_snapshot(self):
        """A valid Git ID must not itself authorize low-level release effects."""
        with (
            patch.object(dual.core, "require_canonical_deployment_lock_held"),
            patch.object(dual, "observe_authoritative_routing", return_value=routing(SERVING)),
            patch.object(dual.core, "snapshot_from_git") as snapshot,
            patch.object(dual.core, "build_release") as build,
        ):
            with self.assertRaisesRegex(RuntimeError, "release admission"):
                dual.core.deploy(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), timeout_seconds=1,
                    expected_head=TARGET,
                )
        snapshot.assert_not_called()
        build.assert_not_called()

    def test_callable_dual_deploy_refuses_valid_nonserving_head_pre_preflight(self):
        """A direct deploy_url() caller may not bypass the main() lock guard."""
        with (
            patch.object(dual.core, "require_canonical_deployment_lock_held"),
            patch.object(dual, "observe_authoritative_routing", return_value=routing(SERVING)),
            patch.object(dual, "preflight_url", side_effect=AssertionError("preflight reached")) as preflight,
            patch.object(dual.core, "build_release") as build,
        ):
            with self.assertRaisesRegex(RuntimeError, "release admission"):
                dual.deploy_url(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), timeout_seconds=1,
                    expected_head=TARGET,
                )
        preflight.assert_not_called()
        build.assert_not_called()

    def test_core_deploy_without_explicit_expected_head_has_no_effect(self):
        """No direct core.deploy bypass via the optional None source identity."""
        with (
            patch.object(dual.core, "snapshot_from_git") as snapshot,
            patch.object(dual.core, "build_release") as build,
        ):
            with self.assertRaises((TypeError, dual.core.DeployError)):
                dual.core.deploy(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), timeout_seconds=1,
                )
        snapshot.assert_not_called()
        build.assert_not_called()

    def test_dual_deploy_url_without_exact_expected_head_has_no_effect(self):
        """The direct callable URL path must not infer an unreviewed source."""
        with (
            patch.object(dual, "preflight_url") as preflight,
            patch.object(dual.core, "build_release") as build,
        ):
            with self.assertRaisesRegex(dual.core.DeployError, "expected_head"):
                dual.deploy_url(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), timeout_seconds=1,
                )
        preflight.assert_not_called()
        build.assert_not_called()

    def test_blue_green_prepare_refuses_mismatched_repo_snapshot_before_build(self):
        """Grok source-drift P1: A serving source cannot build Git target B."""
        with (
            patch.object(dual.core, "require_canonical_deployment_lock_held"),
            patch.object(dual, "require_locked_release_source_admission"),
            patch.object(
                dual.core, "snapshot_from_git",
                return_value=SimpleNamespace(repo_head=TARGET),
            ),
            patch.object(dual.core, "require_runtime_replaceable") as runtime_effect,
            patch.object(dual.core, "build_release") as build,
        ):
            with self.assertRaisesRegex(dual.core.DeployError, "expected_head"):
                dual.prepare_production_blue_green_runtime(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), expected_head=SERVING,
                    cutover_id="repo-head-drift", timeout_seconds=1,
                )
        runtime_effect.assert_not_called()
        build.assert_not_called()

    def test_direct_deploy_url_refuses_mismatched_repo_snapshot_before_build(self):
        with (
            patch.object(dual.core, "require_canonical_deployment_lock_held"),
            # Verify snapshot drift independently of the outer admission gate.
            patch.object(dual, "require_locked_release_source_admission"),
            patch.object(
                dual.core, "snapshot_from_git",
                return_value=SimpleNamespace(repo_head=TARGET),
            ),
            patch.object(dual.core, "require_runtime_replaceable") as runtime_effect,
            patch.object(dual.core, "build_release") as build,
        ):
            with self.assertRaisesRegex(dual.core.DeployError, "expected_head"):
                dual.deploy_url(
                    Path("/synthetic"), Path("/synthetic/runtime"),
                    Path("/synthetic/profile"), timeout_seconds=1,
                    expected_head=SERVING,
                )
        runtime_effect.assert_not_called()
        build.assert_not_called()

    def test_source_equal_check_never_treats_missing_fields_as_authority(self):
        invalid = routing(SERVING)
        invalid["selector"]["runtime_binding_sha256"] = None
        invalid["ingress"]["runtime_binding_sha256"] = None
        material = {name: invalid[name] for name in ("authoritative", "selector", "ingress")}
        invalid["readback_sha256"] = dual._json_sha256(material)
        with patch.object(dual, "observe_authoritative_routing", return_value=invalid):
            with self.assertRaisesRegex(Exception, "release admission|serving identity"):
                dual.require_locked_release_source_admission(expected_head=SERVING)


if __name__ == "__main__":
    unittest.main()
