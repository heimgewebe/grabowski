from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "grabowski_rootbroker_cutover.py"
MODULE_NAME = "grabowski_rootbroker_cutover_test"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("grabowski_rootbroker_cutover.py could not be loaded")
cutover = importlib.util.module_from_spec(SPEC)
sys.modules[MODULE_NAME] = cutover
SPEC.loader.exec_module(cutover)


HEAD = "a" * 40


def _publisher() -> dict[str, object]:
    return {
        "enabled": True,
        "mode": "recovery-marker-publish",
        "source_path": "/home/alex/.local/state/grabowski/recovery/last-server-recovery.json",
        "destination_path": "/var/lib/grabowski/power-worker-recovery-gate.json",
        "expected_source_uid": 1000,
        "max_recovery_age_seconds": 86400,
        "configured_target": cutover.CONFIGURED_TARGET,
        "kill_switch_path": "/home/alex/.local/state/grabowski/operator-kill-switch",
        "require_root_owned_destination": True,
    }


def _power_action() -> dict[str, object]:
    return {
        "enabled": True,
        "mode": "argv-json",
        "target_pattern": r"\{.{1,49152}\}",
        "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
        "timeout_seconds": 600,
        "max_argv": 128,
        "allow_shell": False,
        "gate": {
            "kill_switch_path": "/home/alex/.local/state/grabowski/operator-kill-switch",
            "recovery_marker_path": "/var/lib/grabowski/power-worker-recovery-gate.json",
            "max_recovery_age_seconds": 86400,
            "require_root_owned_gate_files": True,
        },
    }


def _installed_config() -> dict[str, object]:
    return {
        "schema_version": 2,
        "actions": {
            "edit_system_service": {
                "enabled": False,
                "target_pattern": "[A-Za-z0-9_.@:-]{1,200}",
                "argv": ["/usr/bin/systemctl", "restart", "{target}"],
                "timeout_seconds": 120,
            },
            cutover.POWER_ACTION: _power_action(),
        },
    }


def _example_config_text() -> str:
    return json.dumps(
        {
            "schema_version": 2,
            "actions": {cutover.PUBLISH_ACTION: _publisher()},
        },
        sort_keys=True,
    ) + "\n"


def _completed(
    argv: list[str],
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class FakeRunner:
    def __init__(
        self,
        *,
        head: str = HEAD,
        blobs: dict[str, str] | None = None,
        active: bool = True,
        fail_first_start: bool = False,
        active_instance_output: str = "",
        is_active_returncode: int | None = None,
    ) -> None:
        self.head = head
        self.blobs = blobs or {
            "config/privileged-actions.example.json": _example_config_text(),
        }
        self.active = active
        self.fail_first_start = fail_first_start
        self.active_instance_output = active_instance_output
        self.is_active_returncode = is_active_returncode
        self.start_failures = 0
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if argv[:1] == ["/usr/bin/git"] and argv[-2:] == ["rev-parse", "HEAD"]:
            return _completed(argv, stdout=self.head + "\n")
        if argv[:1] == ["/usr/bin/git"] and "show" in argv:
            revision_path = argv[-1]
            commit_id, relative_path = revision_path.split(":", 1)
            if commit_id != self.head or relative_path not in self.blobs:
                return _completed(argv, returncode=1, stderr="missing blob")
            return _completed(argv, stdout=self.blobs[relative_path])
        if argv[:3] == ["/usr/bin/systemctl", "is-active", "--quiet"]:
            returncode = (
                self.is_active_returncode
                if self.is_active_returncode is not None
                else (0 if self.active else 3)
            )
            return _completed(argv, returncode=returncode)
        if argv[:2] == ["/usr/bin/systemctl", "stop"]:
            self.active = False
            return _completed(argv)
        if argv[:3] == ["/usr/bin/systemctl", "list-units", "--type=service"]:
            return _completed(argv, stdout=self.active_instance_output)
        if argv == ["/usr/bin/systemctl", "daemon-reload"]:
            return _completed(argv)
        if argv[:2] == ["/usr/bin/systemctl", "start"]:
            if self.fail_first_start and self.start_failures == 0:
                self.start_failures += 1
                return _completed(argv, returncode=1, stderr="injected start failure")
            self.active = True
            return _completed(argv)
        return _completed(argv, returncode=1, stderr="unexpected command")


class RootbrokerCutoverTests(unittest.TestCase):
    def test_merge_adds_only_publisher_and_target_binding(self) -> None:
        current = _installed_config()
        original = json.loads(json.dumps(current))

        merged, evidence = cutover.merge_privileged_config(
            current,
            publisher=_publisher(),
        )

        self.assertEqual(current, original)
        self.assertEqual(
            merged["actions"][cutover.PUBLISH_ACTION],
            _publisher(),
        )
        expected_power = _power_action()
        expected_power["gate"]["configured_target"] = cutover.CONFIGURED_TARGET
        self.assertEqual(merged["actions"][cutover.POWER_ACTION], expected_power)
        self.assertEqual(
            merged["actions"]["edit_system_service"],
            original["actions"]["edit_system_service"],
        )
        self.assertIn("operator_power_before_sha256", evidence)
        self.assertIn("publisher_sha256", evidence)

    def test_merge_rejects_disabled_operator_power_action(self) -> None:
        current = _installed_config()
        current["actions"][cutover.POWER_ACTION]["enabled"] = False

        with self.assertRaisesRegex(cutover.CutoverError, "not enabled"):
            cutover.merge_privileged_config(current, publisher=_publisher())

    def test_merge_rejects_incoherent_gate_contract(self) -> None:
        current = _installed_config()
        current["actions"][cutover.POWER_ACTION]["gate"][
            "max_recovery_age_seconds"
        ] = 3600

        with self.assertRaisesRegex(cutover.CutoverError, "max_recovery_age_seconds"):
            cutover.merge_privileged_config(current, publisher=_publisher())

    def test_running_helper_matches_commit_bound_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            running = Path(raw) / "cutover.py"
            data = b"VALUE = 'bound helper'\n"
            running.write_bytes(data)
            running.chmod(0o755)
            artifacts = {
                cutover.CUTOVER_HELPER_TARGET: (
                    data,
                    0o755,
                    hashlib.sha256(data).hexdigest(),
                )
            }

            cutover._verify_running_helper(
                artifacts,
                running_path=running,
            )

    def test_running_helper_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            running = Path(raw) / "cutover.py"
            running.write_text("VALUE = 'drifted helper'\n", encoding="utf-8")
            running.chmod(0o755)
            expected = b"VALUE = 'bound helper'\n"
            artifacts = {
                cutover.CUTOVER_HELPER_TARGET: (
                    expected,
                    0o755,
                    hashlib.sha256(expected).hexdigest(),
                )
            }

            with self.assertRaisesRegex(cutover.CutoverError, "differs"):
                cutover._verify_running_helper(
                    artifacts,
                    running_path=running,
                )

    def test_recovery_source_dropin_is_exact_and_narrow(self) -> None:
        publisher = _publisher()
        expected = (
            "[Service]\n"
            "ProtectHome=tmpfs\n"
            "BindReadOnlyPaths=\n"
            "BindReadOnlyPaths=/home/alex/.local/state/grabowski/recovery/"
            "last-server-recovery.json\n"
            "BindReadOnlyPaths=-/home/alex/.local/state/grabowski/"
            "operator-kill-switch\n"
        ).encode("utf-8")
        artifacts = {
            cutover.RECOVERY_SOURCE_DROPIN_TARGET: (
                expected,
                0o644,
                hashlib.sha256(expected).hexdigest(),
            )
        }

        cutover._validate_recovery_source_dropin(
            artifacts,
            publisher=publisher,
        )
        self.assertEqual(
            cutover._expected_recovery_source_dropin(publisher),
            expected,
        )

        broad = expected.replace(
            b"recovery/last-server-recovery.json",
            b"recovery",
        )
        artifacts[cutover.RECOVERY_SOURCE_DROPIN_TARGET] = (
            broad,
            0o644,
            hashlib.sha256(broad).hexdigest(),
        )
        with self.assertRaisesRegex(cutover.CutoverError, "differs"):
            cutover._validate_recovery_source_dropin(
                artifacts,
                publisher=publisher,
            )

    def test_current_recovery_dropin_binds_legacy_not_canonical_marker(self) -> None:
        publisher = _publisher()
        publisher["kill_switch_path"] = (
            "/var/lib/grabowski/operator-blockade/operator-kill-switch"
        )
        publisher["legacy_kill_switch_path"] = (
            "/home/alex/.local/state/grabowski/operator-kill-switch"
        )

        generated = cutover._expected_recovery_source_dropin(publisher)

        self.assertIn(
            b"BindReadOnlyPaths=-/home/alex/.local/state/grabowski/"
            b"operator-kill-switch\n",
            generated,
        )
        self.assertNotIn(b"/var/lib/grabowski/operator-blockade", generated)

    def test_recovery_dropin_rejects_unsafe_explicit_legacy_path(self) -> None:
        publisher = _publisher()
        publisher["legacy_kill_switch_path"] = "/home/alex/unsafe marker"

        with self.assertRaisesRegex(
            cutover.CutoverError, "forbidden whitespace"
        ):
            cutover._expected_recovery_source_dropin(publisher)

    def test_publisher_is_loaded_from_bound_commit_not_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repository = Path(raw)
            mutable = repository / "config"
            mutable.mkdir()
            (mutable / "privileged-actions.example.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            runner = FakeRunner()

            publisher = cutover._publisher_from_repository(
                repository,
                expected_head=HEAD,
                runner=runner,
            )

            self.assertEqual(publisher, _publisher())
            self.assertIn(
                cutover._git_argv(
                    repository,
                    "show",
                    f"{HEAD}:config/privileged-actions.example.json",
                ),
                runner.calls,
            )

    def _layout(self, root: Path) -> dict[str, object]:
        repository = root / "repo"
        repository.mkdir()
        install_root = root / "installed"
        config_parent = install_root / "etc" / "grabowski"
        module_parent = install_root / "usr" / "local" / "lib" / "grabowski"
        wrapper_parent = install_root / "usr" / "local" / "libexec"
        client_parent = install_root / "usr" / "local" / "bin"
        for directory in (config_parent, module_parent, wrapper_parent, client_parent):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)

        config_target = config_parent / "privileged-actions.json"
        config_target.write_text(
            json.dumps(_installed_config(), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        config_target.chmod(0o600)

        module_target = module_parent / "grabowski_privileged_broker.py"
        wrapper_target = wrapper_parent / "grabowski-privileged-broker"
        client_target = client_parent / "grabowski-privileged-request"
        originals = {
            module_target: (b"old module\n", 0o644),
            wrapper_target: (b"old wrapper\n", 0o755),
            client_target: (b"old client\n", 0o755),
        }
        for path, (data, mode) in originals.items():
            path.write_bytes(data)
            path.chmod(mode)

        desired_data = {
            module_target: (b"VALUE = 'new module'\n", 0o644),
            wrapper_target: (
                b"#!/usr/bin/env python3\nVALUE = 'new wrapper'\n",
                0o755,
            ),
            client_target: (
                b"#!/usr/bin/env python3\nVALUE = 'new client'\n",
                0o755,
            ),
        }
        artifacts = {
            path: (data, mode, hashlib.sha256(data).hexdigest())
            for path, (data, mode) in desired_data.items()
        }
        backup_root = root / "backups"
        receipt_root = root / "receipts"
        return {
            "repository": repository,
            "config_target": config_target,
            "module_target": module_target,
            "artifacts": artifacts,
            "originals": originals,
            "desired_data": desired_data,
            "backup_root": backup_root,
            "receipt_root": receipt_root,
            "lock_path": root / "cutover.lock",
        }

    def test_apply_installs_exact_artifacts_and_writes_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            runner = FakeRunner(active=True)

            receipt = cutover.apply_cutover(
                repository=layout["repository"],
                expected_head=HEAD,
                backup_root=layout["backup_root"],
                receipt_root=layout["receipt_root"],
                config_target=layout["config_target"],
                artifact_targets=layout["artifacts"],
                lock_path=layout["lock_path"],
                runner=runner,
                require_root=False,
            )

            self.assertTrue(receipt["success"])
            self.assertFalse(receipt["rollback_performed"])
            self.assertTrue(receipt["daemon_reload_complete"])
            self.assertIn(
                ["/usr/bin/systemctl", "daemon-reload"],
                runner.calls,
            )
            self.assertTrue(runner.active)
            for path, (data, mode) in layout["desired_data"].items():
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat().st_mode & 0o777, mode)
            installed_config = json.loads(layout["config_target"].read_text())
            self.assertEqual(
                installed_config["actions"][cutover.PUBLISH_ACTION],
                _publisher(),
            )
            power = installed_config["actions"][cutover.POWER_ACTION]
            self.assertEqual(
                power["gate"]["configured_target"],
                cutover.CONFIGURED_TARGET,
            )
            self.assertEqual(layout["config_target"].stat().st_mode & 0o777, 0o600)
            receipt_path = Path(receipt["receipt_path"])
            self.assertTrue(receipt_path.is_file())
            self.assertEqual(
                hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                receipt["receipt_sha256"],
            )
            backup_manifests = list(Path(layout["backup_root"]).rglob("manifest.json"))
            self.assertEqual(len(backup_manifests), 1)

    def test_failure_restores_every_preimage_and_records_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            initial_config = layout["config_target"].read_bytes()
            runner = FakeRunner(active=True, fail_first_start=True)

            with self.assertRaisesRegex(cutover.CutoverError, "injected start failure"):
                cutover.apply_cutover(
                    repository=layout["repository"],
                    expected_head=HEAD,
                    backup_root=layout["backup_root"],
                    receipt_root=layout["receipt_root"],
                    config_target=layout["config_target"],
                    artifact_targets=layout["artifacts"],
                        lock_path=layout["lock_path"],
                    runner=runner,
                    require_root=False,
                )

            self.assertTrue(runner.active)
            self.assertEqual(layout["config_target"].read_bytes(), initial_config)
            for path, (data, mode) in layout["originals"].items():
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat().st_mode & 0o777, mode)
            receipts = list(Path(layout["receipt_root"]).glob("*.json"))
            self.assertEqual(len(receipts), 1)
            failure = json.loads(receipts[0].read_text())
            self.assertFalse(failure["success"])
            self.assertTrue(failure["rollback_performed"])
            self.assertIn("injected start failure", failure["error"])

    def test_invalid_python_source_is_rejected_before_backup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            artifacts = dict(layout["artifacts"])
            invalid = b"this is not valid Python !!!\n"
            artifacts[layout["module_target"]] = (
                invalid,
                0o644,
                hashlib.sha256(invalid).hexdigest(),
            )

            with self.assertRaisesRegex(cutover.CutoverError, "not valid Python"):
                cutover.apply_cutover(
                    repository=layout["repository"],
                    expected_head=HEAD,
                    backup_root=layout["backup_root"],
                    receipt_root=layout["receipt_root"],
                    config_target=layout["config_target"],
                    artifact_targets=artifacts,
                    lock_path=layout["lock_path"],
                    runner=FakeRunner(),
                    require_root=False,
                )

            self.assertFalse(Path(layout["backup_root"]).exists())
            self.assertFalse(Path(layout["receipt_root"]).exists())

    def test_lock_contention_fails_before_backup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            descriptor = os.open(
                layout["lock_path"],
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
                0o600,
            )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(cutover.CutoverError, "already running"):
                    cutover.apply_cutover(
                        repository=layout["repository"],
                        expected_head=HEAD,
                        backup_root=layout["backup_root"],
                        receipt_root=layout["receipt_root"],
                        config_target=layout["config_target"],
                        artifact_targets=layout["artifacts"],
                        lock_path=layout["lock_path"],
                        runner=FakeRunner(),
                        require_root=False,
                    )
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

            self.assertFalse(Path(layout["backup_root"]).exists())

    def test_symlink_lock_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            victim = Path(raw) / "victim"
            victim.write_text("do not touch\n", encoding="utf-8")
            layout["lock_path"].symlink_to(victim)

            with self.assertRaisesRegex(cutover.CutoverError, "safely open"):
                cutover.apply_cutover(
                    repository=layout["repository"],
                    expected_head=HEAD,
                    backup_root=layout["backup_root"],
                    receipt_root=layout["receipt_root"],
                    config_target=layout["config_target"],
                    artifact_targets=layout["artifacts"],
                    lock_path=layout["lock_path"],
                    runner=FakeRunner(),
                    require_root=False,
                )

            self.assertEqual(victim.read_text(encoding="utf-8"), "do not touch\n")

    def test_preimage_drift_is_rejected_and_restored(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            original_backup = cutover._backup_preimages

            def backup_then_drift(*args, **kwargs):
                result = original_backup(*args, **kwargs)
                layout["module_target"].write_text("drifted\n", encoding="utf-8")
                layout["module_target"].chmod(0o644)
                return result

            with patch.object(
                cutover,
                "_backup_preimages",
                side_effect=backup_then_drift,
            ):
                with self.assertRaisesRegex(cutover.CutoverError, "changed after preimage"):
                    cutover.apply_cutover(
                        repository=layout["repository"],
                        expected_head=HEAD,
                        backup_root=layout["backup_root"],
                        receipt_root=layout["receipt_root"],
                        config_target=layout["config_target"],
                        artifact_targets=layout["artifacts"],
                        lock_path=layout["lock_path"],
                        runner=FakeRunner(),
                        require_root=False,
                    )

            self.assertEqual(
                layout["module_target"].read_bytes(),
                layout["originals"][layout["module_target"]][0],
            )

    def test_active_request_instance_blocks_file_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            runner = FakeRunner(
                active=True,
                active_instance_output=(
                    "grabowski-privileged-broker@request.service loaded active running\n"
                ),
            )

            with self.assertRaisesRegex(cutover.CutoverError, "active Rootbroker"):
                cutover.apply_cutover(
                    repository=layout["repository"],
                    expected_head=HEAD,
                    backup_root=layout["backup_root"],
                    receipt_root=layout["receipt_root"],
                    config_target=layout["config_target"],
                    artifact_targets=layout["artifacts"],
                    lock_path=layout["lock_path"],
                    runner=runner,
                    require_root=False,
                )

            self.assertTrue(runner.active)
            for path, (data, mode) in layout["originals"].items():
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat().st_mode & 0o777, mode)

    def test_success_receipt_failure_triggers_full_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            initial_config = layout["config_target"].read_bytes()
            original_install = cutover._atomic_install
            injected = False

            def fail_first_success_receipt(target, data, **kwargs):
                nonlocal injected
                if target.parent == layout["receipt_root"] and not injected:
                    injected = True
                    raise cutover.CutoverError("injected receipt write failure")
                return original_install(target, data, **kwargs)

            with patch.object(
                cutover,
                "_atomic_install",
                side_effect=fail_first_success_receipt,
            ):
                with self.assertRaisesRegex(cutover.CutoverError, "receipt write failure"):
                    cutover.apply_cutover(
                        repository=layout["repository"],
                        expected_head=HEAD,
                        backup_root=layout["backup_root"],
                        receipt_root=layout["receipt_root"],
                        config_target=layout["config_target"],
                        artifact_targets=layout["artifacts"],
                        lock_path=layout["lock_path"],
                        runner=FakeRunner(),
                        require_root=False,
                    )

            self.assertEqual(layout["config_target"].read_bytes(), initial_config)
            for path, (data, mode) in layout["originals"].items():
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat().st_mode & 0o777, mode)
            receipts = list(Path(layout["receipt_root"]).glob("*.json"))
            self.assertEqual(len(receipts), 1)
            failure = json.loads(receipts[0].read_text())
            self.assertFalse(failure["success"])
            self.assertTrue(failure["rollback_complete"])
            self.assertIn("receipt write failure", failure["error"])

    def test_inactive_socket_is_rejected_before_backup_or_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            initial_config = layout["config_target"].read_bytes()
            runner = FakeRunner(active=False)

            with self.assertRaisesRegex(cutover.CutoverError, "must be active"):
                cutover.apply_cutover(
                    repository=layout["repository"],
                    expected_head=HEAD,
                    backup_root=layout["backup_root"],
                    receipt_root=layout["receipt_root"],
                    config_target=layout["config_target"],
                    artifact_targets=layout["artifacts"],
                    lock_path=layout["lock_path"],
                    runner=runner,
                    require_root=False,
                )

            self.assertFalse(runner.active)
            self.assertEqual(layout["config_target"].read_bytes(), initial_config)
            for path, (data, mode) in layout["originals"].items():
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(path.stat().st_mode & 0o777, mode)
            self.assertFalse(Path(layout["backup_root"]).exists())
            self.assertFalse(Path(layout["receipt_root"]).exists())

    def test_socket_probe_failure_is_rejected_before_backup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            runner = FakeRunner(active=True, is_active_returncode=1)

            with self.assertRaisesRegex(cutover.CutoverError, "cannot determine"):
                cutover.apply_cutover(
                    repository=layout["repository"],
                    expected_head=HEAD,
                    backup_root=layout["backup_root"],
                    receipt_root=layout["receipt_root"],
                    config_target=layout["config_target"],
                    artifact_targets=layout["artifacts"],
                    lock_path=layout["lock_path"],
                    runner=runner,
                    require_root=False,
                )

            self.assertFalse(Path(layout["backup_root"]).exists())
            self.assertFalse(Path(layout["receipt_root"]).exists())

    def test_apply_rejects_head_drift_before_backup_or_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            layout = self._layout(Path(raw))
            runner = FakeRunner(head="b" * 40)

            with self.assertRaisesRegex(cutover.CutoverError, "differs"):
                cutover.apply_cutover(
                    repository=layout["repository"],
                    expected_head=HEAD,
                    backup_root=layout["backup_root"],
                    receipt_root=layout["receipt_root"],
                    config_target=layout["config_target"],
                    artifact_targets=layout["artifacts"],
                        lock_path=layout["lock_path"],
                    runner=runner,
                    require_root=False,
                )

            self.assertFalse(Path(layout["backup_root"]).exists())
            self.assertFalse(Path(layout["receipt_root"]).exists())


if __name__ == "__main__":
    unittest.main()
