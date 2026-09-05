from __future__ import annotations

import asyncio
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

    async def test_half_closed_connection_is_bounded(self) -> None:
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

    async def test_connection_limiter_rejects_excess_without_waiting(self) -> None:
        limiter = bridge.ConnectionLimiter(1)
        self.assertTrue(await limiter.try_acquire())
        self.assertFalse(await limiter.try_acquire())
        self.assertEqual(limiter.active, 1)
        await limiter.release()
        self.assertTrue(await limiter.try_acquire())
        await limiter.release()
        self.assertEqual(limiter.active, 0)

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
            "LimitNOFILE=256",
            "TasksMax=64",
            "MemoryMax=128M",
            "Restart=on-failure",
        ):
            self.assertIn(required, unit)
        self.assertIn(
            "%h/.local/libexec/grabowski/grabowski_maulwurf_x_public_bridge.py",
            unit,
        )
        self.assertNotIn("tailscale", unit.lower())
        self.assertNotIn("token", unit.lower())
        self.assertNotIn("8443", unit)

    def test_installer_is_idempotent_and_secret_free(self) -> None:
        with (
            tempfile.TemporaryDirectory() as source_tmp,
            tempfile.TemporaryDirectory() as home_tmp,
        ):
            source_root = Path(source_tmp)
            for relative in (installer.BRIDGE_RELATIVE, installer.UNIT_RELATIVE):
                target = source_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)

            first = installer.install(source_root, Path(home_tmp), activate=False)
            second = installer.install(source_root, Path(home_tmp), activate=False)

            self.assertTrue(first["installed"]["bridge"]["changed"])
            self.assertTrue(first["installed"]["unit"]["changed"])
            self.assertFalse(second["installed"]["bridge"]["changed"])
            self.assertFalse(second["installed"]["unit"]["changed"])
            self.assertFalse(second["tailscale_mutated"])
            self.assertFalse(second["secret_material_required"])
            self.assertEqual(second["installed"]["bridge"]["mode"], "0755")
            self.assertEqual(second["installed"]["unit"]["mode"], "0644")


if __name__ == "__main__":
    unittest.main()
