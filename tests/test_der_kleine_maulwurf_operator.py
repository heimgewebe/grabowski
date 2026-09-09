from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import der_kleine_maulwurf_operator as mole  # noqa: E402
import grabowski_tasks as tasks  # noqa: E402


class _TestIcon:
    def __init__(self, *, src: str, mimeType: str | None = None, sizes=None):
        self.src = src
        self.mimeType = mimeType
        self.sizes = sizes


class TestDerKleineMaulwurfOperator(unittest.TestCase):
    def test_source_asset_matches_embedded_icon(self) -> None:
        asset = SRC / "der_kleine_maulwurf_logo_512.png"
        payload = asset.read_bytes()

        self.assertEqual(mole.ICON_BYTES, len(payload))
        self.assertEqual(mole.ICON_SHA256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(payload, mole.icon_bytes())
        self.assertTrue(payload.startswith(b"\x89PNG\r\n\x1a\n"))
        width, height = struct.unpack(">II", payload[16:24])
        self.assertEqual((512, 512), (width, height))

    def test_icon_data_uri_is_valid_png(self) -> None:
        prefix = "data:image/png;base64,"
        uri = mole.icon_data_uri()

        self.assertTrue(uri.startswith(prefix))
        decoded = base64.b64decode(uri.removeprefix(prefix), validate=True)
        self.assertEqual(mole.ICON_SHA256, hashlib.sha256(decoded).hexdigest())

    def test_mcp_icons_uses_public_icon_type(self) -> None:
        fake_mcp = types.ModuleType("mcp")
        fake_types = types.ModuleType("mcp.types")
        fake_types.Icon = _TestIcon
        fake_mcp.types = fake_types

        with patch.dict(sys.modules, {"mcp": fake_mcp, "mcp.types": fake_types}):
            icons = mole.mcp_icons()

        self.assertEqual(1, len(icons))
        icon = icons[0]
        self.assertEqual("image/png", icon.mimeType)
        self.assertEqual(["512x512"], icon.sizes)
        self.assertEqual(mole.icon_data_uri(), icon.src)

    def test_branding_provider_uses_no_private_fastmcp_state(self) -> None:
        source = (SRC / "der_kleine_maulwurf_operator.py").read_text(encoding="utf-8")
        self.assertNotIn("_mcp_server", source)
        self.assertNotIn("grabowski_operator", source)

    def test_core_selects_branding_at_public_fastmcp_constructor(self) -> None:
        source = (SRC / "grabowski_mcp.py").read_text(encoding="utf-8")
        self.assertIn(
            'MCP_BRANDING_VARIANT_ENV = "GRABOWSKI_MCP_BRANDING_VARIANT"',
            source,
        )
        self.assertIn(
            'DER_KLEINE_MAULWURF_BRANDING_VARIANT = "der-kleine-maulwurf"', source
        )
        self.assertIn(
            'LEGACY_KLEINER_MAULWURF_BRANDING_VARIANT = "kleiner-maulwurf"', source
        )
        self.assertIn(
            'DER_KLEINE_MAULWURF_APP_NAME = "der kleine maulwurf"', source
        )
        self.assertIn(
            "from der_kleine_maulwurf_operator import mcp_icons", source
        )
        self.assertIn("_configured_app_name, _configured_icons", source)

    def test_recovery_mode_defaults_normal_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            initial = mole.recovery_mode_status(path=path)
            self.assertEqual("normal", initial["mode"])
            self.assertTrue(initial["valid"])
            self.assertFalse(initial["present"])
            self.assertFalse(mole.recovery_mode_enabled(path=path))

            enabled = mole.enable_recovery_mode("test-recovery", path=path)
            self.assertEqual("recovery", enabled["mode"])
            self.assertTrue(mole.recovery_mode_enabled(path=path))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

            disabled = mole.disable_recovery_mode(path=path)
            self.assertEqual("normal", disabled["mode"])
            self.assertFalse(mole.recovery_mode_enabled(path=path))

    def test_recovery_status_rejects_in_place_change_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            mole.enable_recovery_mode("test-recovery", path=path)
            real_fstat = mole.os.fstat
            calls = 0

            def changed_after_read(descriptor: int):
                nonlocal calls
                calls += 1
                value = real_fstat(descriptor)
                if calls != 2:
                    return value
                return types.SimpleNamespace(
                    st_dev=value.st_dev,
                    st_ino=value.st_ino,
                    st_mode=value.st_mode,
                    st_uid=value.st_uid,
                    st_nlink=value.st_nlink,
                    st_size=value.st_size,
                    st_mtime_ns=value.st_mtime_ns + 1,
                    st_ctime_ns=value.st_ctime_ns + 1,
                )

            with patch.object(mole.os, "fstat", side_effect=changed_after_read):
                status = mole.recovery_mode_status(path=path)
        self.assertFalse(status["valid"])
        self.assertEqual("normal", status["mode"])

    def test_recovery_status_rejects_recovery_document_without_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": mole.RECOVERY_MODE_SCHEMA_VERSION,
                        "kind": mole.RECOVERY_MODE_KIND,
                        "mode": mole.RECOVERY_MODE_RECOVERY,
                        "reason": None,
                        "changed_at_unix": 1,
                    }
                ),
                encoding="utf-8",
            )
            path.chmod(0o600)
            status = mole.recovery_mode_status(path=path)
        self.assertFalse(status["valid"])
        self.assertEqual("normal", status["mode"])

    def test_recovery_guard_fails_fast_while_exclusive_lock_is_held(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            mole.enable_recovery_mode("test-recovery", path=path)
            parent_fd = mole._open_recovery_state_parent(path)
            lock_fd = mole._open_recovery_mode_lock(parent_fd, path)
            mole.os.close(parent_fd)
            mole.fcntl.flock(lock_fd, mole.fcntl.LOCK_EX)
            try:
                with self.assertRaisesRegex(PermissionError, "currently held"):
                    mole.acquire_recovery_mutation_guard(path=path)
            finally:
                mole.fcntl.flock(lock_fd, mole.fcntl.LOCK_UN)
                mole.os.close(lock_fd)

    def test_direct_recovery_cli_rejects_secret_reason(self) -> None:
        reasons = (
            "".join(("Bear", "er ", "abcdefghijklmnopqrst")),
            "".join(("s", "k-", "a" * 24)),
            "".join(("OPENAI_", "TO", "KEN=", "abcdefghijklmnopqrst")),
            "".join(("-----BEGIN ", "TEST PRIVATE ", "KEY-----")),
        )
        for index, reason in enumerate(reasons):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "mode.json"
                with patch.object(mole, "recovery_mode_path", return_value=path):
                    with self.assertRaisesRegex(ValueError, "secret material"):
                        mole.main(["on", "--reason", reason])
                self.assertFalse(path.exists())

    def test_recovery_status_rejects_detector_flagged_persisted_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            fixture_reason = "detector-flagged-fixture-value"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": mole.RECOVERY_MODE_SCHEMA_VERSION,
                        "kind": mole.RECOVERY_MODE_KIND,
                        "mode": mole.RECOVERY_MODE_RECOVERY,
                        "reason": fixture_reason,
                        "changed_at_unix": 1,
                    }
                ),
                encoding="utf-8",
            )
            path.chmod(0o600)
            detector = types.SimpleNamespace(search=lambda _value: object())
            with patch.object(mole, "RECOVERY_REASON_SECRET_PATTERN", detector):
                status = mole.recovery_mode_status(path=path)
        self.assertFalse(status["valid"])
        self.assertEqual("normal", status["mode"])
        self.assertNotIn(fixture_reason, json.dumps(status, sort_keys=True))

    def test_normal_mode_guard_denial_creates_no_lock_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            lock_path = path.with_name(f".{path.name}.lock")
            with self.assertRaisesRegex(PermissionError, "NORMAL mode"):
                mole.acquire_recovery_mutation_guard(path=path)
            self.assertFalse(path.exists())
            self.assertFalse(lock_path.exists())

    def test_recovery_off_drains_active_mutation_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            mole.enable_recovery_mode("test-recovery", path=path)
            guard = mole.acquire_recovery_mutation_guard(path=path)
            started = threading.Event()
            finished = threading.Event()
            outcome: dict[str, object] = {}

            def disable() -> None:
                started.set()
                outcome.update(mole.disable_recovery_mode(path=path))
                finished.set()

            thread = threading.Thread(target=disable)
            thread.start()
            self.assertTrue(started.wait(timeout=1.0))
            time.sleep(0.05)
            self.assertFalse(finished.is_set())
            mole.release_recovery_mutation_guard(guard)
            thread.join(timeout=2.0)
            self.assertFalse(thread.is_alive())
            self.assertEqual("normal", outcome.get("mode"))
            with self.assertRaisesRegex(PermissionError, "NORMAL mode"):
                mole.acquire_recovery_mutation_guard(path=path)

    def test_recovery_off_blocks_new_guards_while_waiting_for_existing_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            mole.enable_recovery_mode("test-recovery", path=path)
            guard = mole.acquire_recovery_mutation_guard(path=path)
            finished = threading.Event()

            def disable() -> None:
                mole.disable_recovery_mode(path=path)
                finished.set()

            thread = threading.Thread(target=disable)
            thread.start()
            marker_path = path.with_name(mole._recovery_transition_marker_name(path))
            deadline = time.monotonic() + 1.0
            while not marker_path.exists():
                if time.monotonic() >= deadline:
                    self.fail("NORMAL transition marker was not published")
                time.sleep(0.005)
            with self.assertRaisesRegex(PermissionError, "transitioning to NORMAL"):
                mole.acquire_recovery_mutation_guard(path=path)
            self.assertFalse(finished.is_set())
            mole.release_recovery_mutation_guard(guard)
            thread.join(timeout=2.0)
            self.assertFalse(thread.is_alive())
            self.assertTrue(finished.is_set())
            self.assertFalse(marker_path.exists())

    def test_recovery_off_times_out_instead_of_waiting_forever(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            mole.enable_recovery_mode("test-recovery", path=path)
            guard = mole.acquire_recovery_mutation_guard(path=path)
            try:
                with (
                    patch.object(mole, "RECOVERY_MODE_LOCK_TIMEOUT_SECONDS", 0.02),
                    self.assertRaisesRegex(RuntimeError, "recovery_mode_lock_timeout"),
                ):
                    mole.disable_recovery_mode(path=path)
            finally:
                mole.release_recovery_mutation_guard(guard)
            self.assertEqual("recovery", mole.recovery_mode_status(path=path)["mode"])
            marker_path = path.with_name(mole._recovery_transition_marker_name(path))
            self.assertFalse(marker_path.exists())

    def test_detached_effect_scan_maps_systemctl_timeout_to_runtime_error(self) -> None:
        with patch.object(
            mole.subprocess,
            "run",
            side_effect=mole.subprocess.TimeoutExpired(cmd=["systemctl"], timeout=5),
        ):
            with self.assertRaisesRegex(RuntimeError, "recovery_detached_unit_state_unavailable"):
                mole.active_recovery_detached_effects()

    def test_detached_effect_scan_maps_tmux_timeout_to_runtime_error(self) -> None:

        def fake_run(argv, **_kwargs):
            if argv[0] == "systemctl":
                return types.SimpleNamespace(returncode=0, stdout="")
            raise mole.subprocess.TimeoutExpired(cmd=argv, timeout=5)

        with (
            patch.object(mole.subprocess, "run", side_effect=fake_run),
            patch.object(tasks, "recovery_active_task_effects", return_value=[]),
            patch.object(mole.Path, "is_file", return_value=True),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "recovery_workspace_session_state_unavailable"
            ):
                mole.active_recovery_detached_effects()

    def test_detached_effect_scan_includes_backend_aware_persistent_tasks(self) -> None:

        def fake_run(argv, **_kwargs):
            if argv[0] == "systemctl":
                return types.SimpleNamespace(returncode=0, stdout="")
            return types.SimpleNamespace(returncode=1, stdout="")

        with (
            patch.object(mole.subprocess, "run", side_effect=fake_run),
            patch.object(
                tasks,
                "recovery_active_task_effects",
                return_value=[
                    "task:root@local:systemd-root-broker:system:root.service:running",
                    "task:remote@node:systemd-user:user:remote.service:running",
                ],
            ),
        ):
            effects = mole.active_recovery_detached_effects()
        self.assertIn("task:root@local:systemd-root-broker:system:root.service:running", effects)
        self.assertIn("task:remote@node:systemd-user:user:remote.service:running", effects)

    def test_post_replace_directory_fsync_failure_is_explicitly_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            real_fsync = mole.os.fsync
            calls = 0

            def fail_directory_fsync(descriptor: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("directory fsync failed")
                real_fsync(descriptor)

            with patch.object(mole.os, "fsync", side_effect=fail_directory_fsync):
                result = mole.enable_recovery_mode("test-recovery", path=path)
            observed = mole.recovery_mode_status(path=path)
        self.assertTrue(result["valid"])
        self.assertTrue(result["ambiguity"])
        self.assertTrue(result["effect_started"])
        self.assertFalse(result["durability_confirmed"])
        self.assertEqual("effect_observed_durability_unknown", result["write_outcome"])
        self.assertEqual("recovery", observed["mode"])

    def test_live_recovery_off_refuses_while_detached_effects_are_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            with patch.object(mole, "recovery_mode_path", return_value=path):
                enabled = mole.enable_recovery_mode("test-recovery")
                self.assertEqual("confirmed", enabled["write_outcome"])
                with patch.object(
                    mole, "active_recovery_detached_effects",
                    return_value=["unit:grabowski-task-test.service"],
                ):
                    with self.assertRaisesRegex(RuntimeError, "detached_effects_active"):
                        mole.disable_recovery_mode()
                self.assertEqual("recovery", mole.recovery_mode_status()["mode"])

    def test_live_recovery_off_succeeds_after_detached_effects_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            with (
                patch.object(mole, "recovery_mode_path", return_value=path),
                patch.object(mole, "active_recovery_detached_effects", return_value=[]),
            ):
                mole.enable_recovery_mode("test-recovery")
                disabled = mole.disable_recovery_mode()
            self.assertTrue(disabled["valid"])
            self.assertEqual("normal", disabled["mode"])
            self.assertEqual("confirmed", disabled["write_outcome"])

    def test_explicit_live_recovery_path_cannot_bypass_detached_effect_drain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            with patch.object(mole, "recovery_mode_path", return_value=path):
                mole.enable_recovery_mode("test-recovery", path=path)
                with patch.object(
                    mole,
                    "active_recovery_detached_effects",
                    return_value=["unit:grabowski-task-test.service"],
                ):
                    with self.assertRaisesRegex(RuntimeError, "detached_effects_active"):
                        mole.disable_recovery_mode(path=path)
                self.assertEqual(
                    "recovery", mole.recovery_mode_status(path=path)["mode"]
                )

    def test_direct_recovery_cli_fails_when_readback_disagrees(self) -> None:
        with (
            patch.object(
                mole,
                "enable_recovery_mode",
                return_value={"valid": False, "mode": "normal"},
            ),
            patch("builtins.print"),
        ):
            self.assertEqual(1, mole.main(["on", "--reason", "primary unavailable"]))
        with (
            patch.object(
                mole,
                "disable_recovery_mode",
                return_value={"valid": True, "mode": "recovery"},
            ),
            patch("builtins.print"),
        ):
            self.assertEqual(1, mole.main(["off"]))
        with (
            patch.object(
                mole,
                "recovery_mode_status",
                return_value={"valid": True, "mode": "normal"},
            ),
            patch("builtins.print"),
        ):
            self.assertEqual(0, mole.main(["status"]))


    def test_oversized_recovery_mode_fails_closed_without_unbounded_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            path.write_bytes(b"x" * (mole.RECOVERY_MODE_MAX_BYTES + 1))
            path.chmod(0o600)
            with patch.object(Path, "read_bytes", side_effect=AssertionError("must not use unbounded read")):
                status = mole.recovery_mode_status(path=path)
        self.assertFalse(status["valid"])
        self.assertEqual("normal", status["mode"])

    def test_invalid_recovery_mode_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            path.write_text("not-json", encoding="utf-8")
            path.chmod(0o600)
            status = mole.recovery_mode_status(path=path)
        self.assertFalse(status["valid"])
        self.assertEqual("normal", status["mode"])

    def test_runtime_contract_installs_branding_provider(self) -> None:
        contract = json.loads((ROOT / "config" / "runtime-entrypoint.json").read_text())
        sources = {
            item["module"]: item["source"]
            for item in contract["supporting_sources"]
        }
        self.assertEqual(
            "src/der_kleine_maulwurf_operator.py",
            sources.get("der_kleine_maulwurf_operator"),
        )


if __name__ == "__main__":
    unittest.main()
