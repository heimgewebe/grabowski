from __future__ import annotations

import asyncio
import contextlib
import io
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import grabowski_maulwurf_x_public_bridge as bridge  # noqa: E402
import install_maulwurf_x_public_bridge as installer  # noqa: E402


class _Reader:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    async def read(self, _size: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _TimedReader:
    def __init__(self, chunks: list[bytes], delay_seconds: float) -> None:
        self._chunks = list(chunks)
        self._delay_seconds = delay_seconds

    async def read(self, _size: int) -> bytes:
        await asyncio.sleep(self._delay_seconds)
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _BlockingReader:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    async def read(self, _size: int) -> bytes:
        await self._event.wait()
        return b""


class _Writer:
    def __init__(self) -> None:
        self.data = bytearray()
        self.eof_count = 0
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        return None

    def write_eof(self) -> None:
        self.eof_count += 1

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _NoHalfCloseWriter(_Writer):
    def write_eof(self) -> None:
        raise NotImplementedError("synthetic TLS-like writer")


def _stage_sources(source_root: Path) -> None:
    for relative in (installer.BRIDGE_RELATIVE, installer.UNIT_RELATIVE):
        target = source_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)


class MaulwurfXPublicBridgeAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_relay_forwards_both_directions_and_handles_half_close(self) -> None:
        config = bridge.BridgeConfig(
            idle_timeout_seconds=1.0,
            half_close_timeout_seconds=0.2,
        )
        client_writer = _Writer()
        upstream_writer = _Writer()
        await bridge._relay_streams(
            _Reader([b"request", b""]),
            client_writer,
            _Reader([b"response", b""]),
            upstream_writer,
            config,
        )
        self.assertEqual(bytes(upstream_writer.data), b"request")
        self.assertEqual(bytes(client_writer.data), b"response")
        self.assertEqual(upstream_writer.eof_count, 1)
        self.assertEqual(client_writer.eof_count, 1)

    async def test_relay_preserves_http_host_and_authorization_bytes(self) -> None:
        request = (
            b"POST /mcp HTTP/1.1\r\n"
            b"Host: wg-prod-1.tail6dbb90.ts.net:10000\r\n"
            b"Authorization: Bearer sentinel-not-a-secret\r\n"
            b"Content-Type: application/json\r\n\r\n{}"
        )
        upstream_writer = _Writer()
        await bridge._relay_streams(
            _Reader([request, b""]),
            _Writer(),
            _Reader([b"HTTP/1.1 401 Unauthorized\r\n\r\n", b""]),
            upstream_writer,
            bridge.BridgeConfig(
                idle_timeout_seconds=1.0,
                half_close_timeout_seconds=0.2,
            ),
        )
        self.assertEqual(bytes(upstream_writer.data), request)

    async def test_idle_connection_is_bounded(self) -> None:
        config = bridge.BridgeConfig(
            idle_timeout_seconds=0.04,
            half_close_timeout_seconds=0.2,
        )
        with self.assertRaises(bridge.BridgeTimeoutError):
            await bridge._relay_streams(
                _BlockingReader(),
                _Writer(),
                _BlockingReader(),
                _Writer(),
                config,
            )

    async def test_half_closed_connection_is_bounded_when_remaining_side_is_idle(
        self,
    ) -> None:
        config = bridge.BridgeConfig(
            idle_timeout_seconds=1.0,
            half_close_timeout_seconds=0.04,
        )
        with self.assertRaises(bridge.BridgeHalfCloseTimeout):
            await bridge._relay_streams(
                _Reader([b""]),
                _Writer(),
                _BlockingReader(),
                _Writer(),
                config,
            )

    async def test_half_close_timeout_is_not_a_live_response_deadline(self) -> None:
        config = bridge.BridgeConfig(
            idle_timeout_seconds=1.0,
            half_close_timeout_seconds=0.04,
        )
        client_writer = _Writer()
        await bridge._relay_streams(
            _Reader([b""]),
            client_writer,
            _TimedReader([b"a", b"b", b"c", b"d", b""], 0.02),
            _Writer(),
            config,
        )
        self.assertEqual(bytes(client_writer.data), b"abcd")

    async def test_pipe_tolerates_writer_without_transport_half_close(self) -> None:
        writer = _NoHalfCloseWriter()
        activity = bridge._ConnectionActivity.now()
        await bridge._pipe(
            _Reader([b"payload", b""]),
            writer,
            activity,
            read_chunk_bytes=1024,
        )
        self.assertEqual(bytes(writer.data), b"payload")

    async def test_connection_limiter_rejects_excess_without_waiting(self) -> None:
        limiter = bridge.ConnectionLimiter(1)
        self.assertTrue(await limiter.try_acquire())
        self.assertFalse(await limiter.try_acquire())
        self.assertEqual(limiter.active, 1)
        await limiter.release()
        self.assertTrue(await limiter.try_acquire())
        await limiter.release()
        self.assertEqual(limiter.active, 0)

    async def test_handle_capacity_rejection_closes_client_without_queueing(
        self,
    ) -> None:
        public_bridge = bridge.PublicBridge(bridge.BridgeConfig(max_connections=1))
        self.assertTrue(await public_bridge._limiter.try_acquire())
        writer = _Writer()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            await public_bridge.handle(_BlockingReader(), writer)
        self.assertTrue(writer.closed)
        self.assertEqual(public_bridge._limiter.active, 1)
        self.assertEqual(
            output.getvalue().strip(), "event=connection_rejected reason=capacity"
        )
        await public_bridge._limiter.release()

    async def test_handle_releases_limiter_after_upstream_connect_failure(self) -> None:
        public_bridge = bridge.PublicBridge(bridge.BridgeConfig(max_connections=1))
        writer = _Writer()
        output = io.StringIO()
        with (
            mock.patch.object(
                bridge,
                "_connect_upstream",
                new=mock.AsyncMock(side_effect=OSError("synthetic upstream failure")),
            ),
            contextlib.redirect_stdout(output),
        ):
            await public_bridge.handle(_Reader([b""]), writer)
        self.assertEqual(public_bridge._limiter.active, 0)
        self.assertTrue(writer.closed)
        self.assertEqual(
            output.getvalue().strip(), "event=connection_error error=OSError"
        )

    async def test_upstream_failure_propagates_without_retry_loop(self) -> None:
        config = bridge.BridgeConfig(connect_timeout_seconds=0.1)
        ssl_context = bridge.ssl.create_default_context()
        with mock.patch.object(
            bridge.asyncio,
            "open_connection",
            new=mock.AsyncMock(side_effect=OSError("synthetic upstream failure")),
        ) as open_connection:
            with self.assertRaises(OSError):
                await bridge._connect_upstream(config, ssl_context)
        open_connection.assert_awaited_once()

    async def test_upstream_connect_timeout_is_bounded(self) -> None:
        async def never_connect(*_args, **_kwargs):
            await asyncio.sleep(60)

        config = bridge.BridgeConfig(connect_timeout_seconds=0.02)
        ssl_context = bridge.ssl.create_default_context()
        with mock.patch.object(bridge.asyncio, "open_connection", new=never_connect):
            with self.assertRaises(asyncio.TimeoutError):
                await bridge._connect_upstream(config, ssl_context)


class MaulwurfXPublicBridgeContractTests(unittest.TestCase):
    def test_defaults_use_hostname_tls_and_loopback_only(self) -> None:
        config = bridge.BridgeConfig()
        config.validate()
        self.assertEqual(config.listen_host, "127.0.0.1")
        self.assertEqual(config.listen_port, 18091)
        self.assertEqual(config.upstream_host, "heim-pc.tail6dbb90.ts.net")
        self.assertEqual(config.server_name, "heim-pc.tail6dbb90.ts.net")
        self.assertEqual(config.upstream_port, 10000)
        self.assertNotRegex(config.upstream_host, r"^\d+\.\d+\.\d+\.\d+$")

    def test_non_loopback_listener_is_rejected(self) -> None:
        for listen_host in ("0.0.0.0", "::", "192.0.2.10"):
            with self.subTest(listen_host=listen_host):
                with self.assertRaisesRegex(ValueError, "listen_host must be loopback"):
                    bridge.BridgeConfig(listen_host=listen_host).validate()
        bridge.BridgeConfig(listen_host="::1").validate()

    def test_ready_log_is_one_structured_line(self) -> None:
        self.assertEqual(
            bridge._ready_log(bridge.BridgeConfig()),
            "event=ready listen=127.0.0.1:18091 "
            "upstream=heim-pc.tail6dbb90.ts.net:10000 max_connections=64",
        )

    def test_systemd_unit_is_hardened_and_does_not_manage_funnel(self) -> None:
        unit = (ROOT / installer.UNIT_RELATIVE).read_text(encoding="utf-8")
        for required in (
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "MemoryDenyWriteExecute=yes",
            "RestrictAddressFamilies=AF_INET AF_INET6",
            "Environment=PYTHONDONTWRITEBYTECODE=1",
            "LimitNOFILE=512",
            "TasksMax=64",
            "MemoryMax=128M",
            "Restart=on-failure",
        ):
            self.assertIn(required, unit)
        self.assertIn(installer.EXPECTED_EXEC_START, unit)
        self.assertNotIn("tailscale", unit.lower())
        self.assertNotIn("token", unit.lower())
        self.assertNotIn("8443", unit)

    def test_installer_is_idempotent_and_secret_free(self) -> None:
        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as home_tmp,
        ):
            source_root = Path(source_tmp)
            _stage_sources(source_root)

            first = installer.install(source_root, Path(home_tmp), activate=False)
            second = installer.install(source_root, Path(home_tmp), activate=False)

            self.assertTrue(first["ok"])
            self.assertTrue(first["installed"]["bridge"]["changed"])
            self.assertTrue(first["installed"]["unit"]["changed"])
            self.assertFalse(second["installed"]["bridge"]["changed"])
            self.assertFalse(second["installed"]["unit"]["changed"])
            self.assertFalse(second["tailscale_mutated"])
            self.assertFalse(second["secret_material_required"])
            self.assertEqual(second["installed"]["bridge"]["mode"], "0755")
            self.assertEqual(second["installed"]["unit"]["mode"], "0644")
            self.assertIsNone(second["activation"]["linger_active"])

    def test_installer_rejects_symlink_source(self) -> None:
        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as home_tmp,
        ):
            source_root = Path(source_tmp)
            unit_target = source_root / installer.UNIT_RELATIVE
            unit_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / installer.UNIT_RELATIVE, unit_target)
            bridge_target = source_root / installer.BRIDGE_RELATIVE
            bridge_target.parent.mkdir(parents=True, exist_ok=True)
            bridge_target.symlink_to(ROOT / installer.BRIDGE_RELATIVE)

            with self.assertRaisesRegex(ValueError, "source is not a regular"):
                installer.install(source_root, Path(home_tmp), activate=False)

    def test_installer_rejects_dangling_symlink_target(self) -> None:
        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as home_tmp,
        ):
            source_root = Path(source_tmp)
            home = Path(home_tmp)
            _stage_sources(source_root)
            bridge_target = home / installer.BRIDGE_TARGET_RELATIVE
            bridge_target.parent.mkdir(parents=True, exist_ok=True)
            bridge_target.symlink_to(home / "missing-bridge-target")

            with self.assertRaisesRegex(ValueError, "target is not a regular"):
                installer.install(source_root, home, activate=False)

    def test_installer_rejects_unit_with_wrong_execstart(self) -> None:
        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as home_tmp,
        ):
            source_root = Path(source_tmp)
            _stage_sources(source_root)
            unit_target = source_root / installer.UNIT_RELATIVE
            unit_target.write_text(
                unit_target.read_text(encoding="utf-8").replace(
                    installer.EXPECTED_EXEC_START, "ExecStart=/bin/false"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "ExecStart"):
                installer.install(source_root, Path(home_tmp), activate=False)

    def test_installer_activation_requires_linger_before_writes(self) -> None:
        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as home_tmp,
        ):
            source_root = Path(source_tmp)
            home = Path(home_tmp)
            _stage_sources(source_root)
            with mock.patch.object(installer, "_linger_active", return_value=False):
                with self.assertRaisesRegex(installer.ActivationError, "linger"):
                    installer.install(source_root, home, activate=True)
            self.assertFalse((home / installer.BRIDGE_TARGET_RELATIVE).exists())
            self.assertFalse((home / installer.UNIT_TARGET_RELATIVE).exists())

    def test_installer_activation_restarts_and_verifies_exact_fragment(self) -> None:
        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as home_tmp,
        ):
            source_root = Path(source_tmp)
            home = Path(home_tmp).resolve()
            _stage_sources(source_root)
            expected_fragment = home / installer.UNIT_TARGET_RELATIVE
            readback = installer.subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=(
                    "LoadState=loaded\n"
                    "ActiveState=active\n"
                    "SubState=running\n"
                    "UnitFileState=enabled\n"
                    "Result=success\n"
                    "NRestarts=0\n"
                    "MainPID=123\n"
                    f"FragmentPath={expected_fragment}\n"
                ),
                stderr="",
            )
            normal = installer.subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            with (
                mock.patch.object(installer, "_linger_active", return_value=True),
                mock.patch.object(
                    installer,
                    "_systemctl",
                    side_effect=[normal, normal, normal, readback],
                ) as systemctl,
            ):
                result = installer.install(source_root, home, activate=True)

            self.assertEqual(
                [call.args for call in systemctl.call_args_list[:3]],
                [
                    ("daemon-reload",),
                    ("enable", installer.UNIT_NAME),
                    ("restart", installer.UNIT_NAME),
                ],
            )
            self.assertTrue(result["activation"]["requested"])
            self.assertTrue(result["activation"]["linger_active"])
            self.assertTrue(result["activation"]["verified"])
            self.assertEqual(
                result["activation"]["systemd_readback"]["FragmentPath"],
                str(expected_fragment),
            )

    def test_installer_activation_rejects_fragmentpath_drift(self) -> None:
        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as home_tmp,
        ):
            source_root = Path(source_tmp)
            home = Path(home_tmp).resolve()
            _stage_sources(source_root)
            readback = installer.subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=(
                    "LoadState=loaded\nActiveState=active\nSubState=running\n"
                    "UnitFileState=enabled\nResult=success\nNRestarts=0\n"
                    "MainPID=123\nFragmentPath=/tmp/wrong.service\n"
                ),
                stderr="",
            )
            normal = installer.subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            with (
                mock.patch.object(installer, "_linger_active", return_value=True),
                mock.patch.object(
                    installer,
                    "_systemctl",
                    side_effect=[normal, normal, normal, readback],
                ),
            ):
                with self.assertRaisesRegex(installer.ActivationError, "FragmentPath"):
                    installer.install(source_root, home, activate=True)

    def test_installer_surfaces_systemctl_failure_as_activation_error(self) -> None:
        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as home_tmp,
        ):
            source_root = Path(source_tmp)
            _stage_sources(source_root)
            with (
                mock.patch.object(installer, "_linger_active", return_value=True),
                mock.patch.object(
                    installer,
                    "_systemctl",
                    side_effect=installer.ActivationError(
                        "systemctl --user daemon-reload failed with exit status 1"
                    ),
                ),
            ):
                with self.assertRaisesRegex(installer.ActivationError, "systemctl"):
                    installer.install(source_root, Path(home_tmp), activate=True)


if __name__ == "__main__":
    unittest.main()
