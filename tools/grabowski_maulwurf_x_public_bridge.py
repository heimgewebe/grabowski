#!/usr/bin/env python3
"""Transparent bounded TCP/TLS bridge for the Maulwurf X public ingress.

Tailscale Funnel terminates public HTTPS on wg-prod-1 and forwards plaintext TCP
HTTP to this loopback listener.  This bridge opens a TLS-verified connection to
the existing heim-pc Funnel.  It deliberately has no HTTP, MCP, credential or
Grabowski policy logic; those authorities stay on the Maulwurf X gateway and
Grabowski operator.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import ssl
import time


DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 18091
DEFAULT_UPSTREAM_HOST = "heim-pc.tail6dbb90.ts.net"
DEFAULT_UPSTREAM_PORT = 10000
DEFAULT_SERVER_NAME = "heim-pc.tail6dbb90.ts.net"


class BridgeTimeoutError(TimeoutError):
    """Raised when an otherwise live connection remains idle too long."""


class BridgeHalfCloseTimeout(TimeoutError):
    """Raised when one side half-closes and the other never finishes."""


@dataclass(frozen=True)
class BridgeConfig:
    listen_host: str = DEFAULT_LISTEN_HOST
    listen_port: int = DEFAULT_LISTEN_PORT
    upstream_host: str = DEFAULT_UPSTREAM_HOST
    upstream_port: int = DEFAULT_UPSTREAM_PORT
    server_name: str = DEFAULT_SERVER_NAME
    connect_timeout_seconds: float = 10.0
    idle_timeout_seconds: float = 600.0
    half_close_timeout_seconds: float = 30.0
    stream_limit_bytes: int = 131_072
    read_chunk_bytes: int = 65_536
    max_connections: int = 64
    listen_backlog: int = 64

    def validate(self) -> None:
        for label, value in (
            ("listen_host", self.listen_host),
            ("upstream_host", self.upstream_host),
            ("server_name", self.server_name),
        ):
            if not value or len(value) > 253:
                raise ValueError(f"{label} is invalid")
        for label, value in (
            ("listen_port", self.listen_port),
            ("upstream_port", self.upstream_port),
        ):
            if isinstance(value, bool) or not 1 <= value <= 65535:
                raise ValueError(f"{label} is invalid")
        for label, value in (
            ("connect_timeout_seconds", self.connect_timeout_seconds),
            ("idle_timeout_seconds", self.idle_timeout_seconds),
            ("half_close_timeout_seconds", self.half_close_timeout_seconds),
        ):
            if value <= 0:
                raise ValueError(f"{label} must be positive")
        if not 4096 <= self.stream_limit_bytes <= 1_048_576:
            raise ValueError("stream_limit_bytes is outside the bounded range")
        if not 1024 <= self.read_chunk_bytes <= self.stream_limit_bytes:
            raise ValueError("read_chunk_bytes is outside the bounded range")
        if not 1 <= self.max_connections <= 512:
            raise ValueError("max_connections is outside the bounded range")
        if not 1 <= self.listen_backlog <= 512:
            raise ValueError("listen_backlog is outside the bounded range")


class ConnectionLimiter:
    """Reject excess accepted connections instead of queueing them in userspace."""

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("connection limit must be positive")
        self._limit = limit
        self._active = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> int:
        return self._active

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self._active >= self._limit:
                return False
            self._active += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            if self._active <= 0:
                raise RuntimeError("connection limiter release without acquire")
            self._active -= 1


@dataclass
class _ConnectionActivity:
    last_activity: float
    first_eof: float | None = None

    @classmethod
    def now(cls) -> "_ConnectionActivity":
        return cls(last_activity=time.monotonic())

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def mark_eof(self) -> None:
        now = time.monotonic()
        self.last_activity = now
        if self.first_eof is None:
            self.first_eof = now


async def _safe_wait_closed(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError, RuntimeError):
        pass


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    activity: _ConnectionActivity,
    *,
    read_chunk_bytes: int,
) -> None:
    while True:
        data = await reader.read(read_chunk_bytes)
        if not data:
            activity.mark_eof()
            try:
                writer.write_eof()
            except (AttributeError, NotImplementedError, OSError, RuntimeError):
                # TLS streams commonly do not support transport half-close.  The
                # opposite direction may still finish normally; the watchdog
                # bounds how long that state can remain open.
                pass
            return
        activity.touch()
        writer.write(data)
        await writer.drain()


async def _connection_watchdog(
    activity: _ConnectionActivity,
    *,
    idle_timeout_seconds: float,
    half_close_timeout_seconds: float,
) -> None:
    interval = max(
        0.01,
        min(1.0, idle_timeout_seconds / 4.0, half_close_timeout_seconds / 4.0),
    )
    while True:
        await asyncio.sleep(interval)
        now = time.monotonic()
        if activity.first_eof is not None:
            if now - activity.first_eof >= half_close_timeout_seconds:
                raise BridgeHalfCloseTimeout("half-closed connection did not drain")
        elif now - activity.last_activity >= idle_timeout_seconds:
            raise BridgeTimeoutError("connection became idle")


async def _relay_streams(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    config: BridgeConfig,
) -> None:
    activity = _ConnectionActivity.now()
    client_to_upstream = asyncio.create_task(
        _pipe(
            client_reader,
            upstream_writer,
            activity,
            read_chunk_bytes=config.read_chunk_bytes,
        )
    )
    upstream_to_client = asyncio.create_task(
        _pipe(
            upstream_reader,
            client_writer,
            activity,
            read_chunk_bytes=config.read_chunk_bytes,
        )
    )
    watchdog = asyncio.create_task(
        _connection_watchdog(
            activity,
            idle_timeout_seconds=config.idle_timeout_seconds,
            half_close_timeout_seconds=config.half_close_timeout_seconds,
        )
    )
    pipes = {client_to_upstream, upstream_to_client}
    try:
        while pipes:
            done, _pending = await asyncio.wait(
                [*pipes, watchdog], return_when=asyncio.FIRST_COMPLETED
            )
            if watchdog in done:
                await watchdog
            for task in tuple(done):
                if task is watchdog:
                    continue
                pipes.discard(task)
                await task
    finally:
        for task in (*pipes, watchdog):
            if not task.done():
                task.cancel()
        await asyncio.gather(*pipes, watchdog, return_exceptions=True)


async def _connect_upstream(
    config: BridgeConfig,
    ssl_context: ssl.SSLContext,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.wait_for(
        asyncio.open_connection(
            config.upstream_host,
            config.upstream_port,
            ssl=ssl_context,
            server_hostname=config.server_name,
            limit=config.stream_limit_bytes,
        ),
        timeout=config.connect_timeout_seconds,
    )


class PublicBridge:
    def __init__(self, config: BridgeConfig) -> None:
        config.validate()
        self.config = config
        self._ssl_context = ssl.create_default_context()
        self._limiter = ConnectionLimiter(config.max_connections)

    async def handle(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        if not await self._limiter.try_acquire():
            print("bridge_connection_rejected=capacity", flush=True)
            await _safe_wait_closed(client_writer)
            return
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            upstream_reader, upstream_writer = await _connect_upstream(
                self.config, self._ssl_context
            )
            await _relay_streams(
                client_reader,
                client_writer,
                upstream_reader,
                upstream_writer,
                self.config,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Exception class is intentionally the only failure detail.  Request
            # bytes, headers, credentials, peer addresses and URLs are not logged.
            print(f"bridge_connection_error={type(exc).__name__}", flush=True)
        finally:
            await _safe_wait_closed(upstream_writer)
            await _safe_wait_closed(client_writer)
            await self._limiter.release()

    async def serve(self) -> None:
        server = await asyncio.start_server(
            self.handle,
            self.config.listen_host,
            self.config.listen_port,
            limit=self.config.stream_limit_bytes,
            backlog=self.config.listen_backlog,
        )
        sockets = server.sockets or []
        if not sockets:
            server.close()
            await server.wait_closed()
            raise RuntimeError("bridge listener missing")
        print(
            "bridge_ready="
            f"{self.config.listen_host}:{self.config.listen_port} "
            f"upstream={self.config.server_name}:{self.config.upstream_port} ",
            f"max_connections={self.config.max_connections}",
            flush=True,
        )
        async with server:
            await server.serve_forever()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST)
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--upstream-host", default=DEFAULT_UPSTREAM_HOST)
    parser.add_argument("--upstream-port", type=int, default=DEFAULT_UPSTREAM_PORT)
    parser.add_argument("--server-name", default=DEFAULT_SERVER_NAME)
    parser.add_argument("--connect-timeout", type=float, default=10.0)
    parser.add_argument("--idle-timeout", type=float, default=600.0)
    parser.add_argument("--half-close-timeout", type=float, default=30.0)
    parser.add_argument("--max-connections", type=int, default=64)
    return parser


def main() -> int:
    args = _parser().parse_args()
    config = BridgeConfig(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        server_name=args.server_name,
        connect_timeout_seconds=args.connect_timeout,
        idle_timeout_seconds=args.idle_timeout,
        half_close_timeout_seconds=args.half_close_timeout,
        max_connections=args.max_connections,
    )
    asyncio.run(PublicBridge(config).serve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
