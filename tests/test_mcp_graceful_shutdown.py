"""Exercise the actual stateless FastMCP SSE shutdown against a real socket.

A normal SIGTERM must not cancel a finite POST response just because
sse-starlette has noticed the signal. Use a separate process and temp HOME,
never the production listener or tool registry.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import httpx


ROOT = Path(__file__).resolve().parents[1]
SERVER = r"""
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
import grabowski_operator as operator
from mcp.server.fastmcp import FastMCP

assert Path(operator.__file__).resolve() == Path(sys.argv[1], "grabowski_operator.py")
port, tmp, delay, budget = int(sys.argv[2]), Path(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
mcp = FastMCP("shutdown-test", host="127.0.0.1", port=port, stateless_http=True, log_level="INFO")

@mcp.tool()
async def slow(value: int) -> str:
    (tmp / f"started-{value}").write_text("started")
    await asyncio.sleep(delay)
    return f"complete-{value}"

operator.HTTP_GRACEFUL_SHUTDOWN_SECONDS = budget
operator._run_http_runtime(mcp)
"""


@unittest.skipUnless(os.name == "posix", "requires POSIX process signals")
class MCPGracefulShutdownTests(unittest.TestCase):
    def _probe(self, *, calls: int, delay: float, budget: int, standalone_get=False):
        with tempfile.TemporaryDirectory(prefix="grabowski-http-shutdown-") as tmp_name:
            tmp = Path(tmp_name)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            env = dict(os.environ)
            env.update(HOME=tmp_name, XDG_CONFIG_HOME=str(tmp / "config"),
                       XDG_STATE_HOME=str(tmp / "state"), XDG_CACHE_HOME=str(tmp / "cache"))
            headers = {
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            }
            url = f"http://127.0.0.1:{port}/mcp"

            def rpc(method, params, request_id, timeout=12):
                with httpx.Client(trust_env=False, timeout=timeout) as client:
                    return client.post(url, json={
                        "jsonrpc": "2.0", "id": request_id,
                        "method": method, "params": params,
                    }, headers=headers)

            with (tmp / "server.log").open("w+") as log:
                proc = subprocess.Popen(
                    [sys.executable, "-c", SERVER, str(ROOT / "src"), str(port),
                     tmp_name, str(delay), str(budget)],
                    cwd=tmp_name, env=env, stdout=log, stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 15
                    while True:
                        try:
                            response = rpc("initialize", {
                                "protocolVersion": "2025-03-26", "capabilities": {},
                                "clientInfo": {"name": "shutdown-test", "version": "1"},
                            }, 100, timeout=1)
                            if response.status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        if proc.poll() is not None or time.monotonic() >= deadline:
                            log.seek(0)
                            self.fail(f"test server did not start:\n{log.read()}")
                        time.sleep(0.05)

                    get_ready = threading.Event()

                    def read_standalone_get():
                        with httpx.Client(trust_env=False, timeout=12) as client:
                            with client.stream("GET", url, headers=headers) as response:
                                if (response.status_code != 200 or
                                        "text/event-stream" not in response.headers.get("content-type", "")):
                                    get_ready.set()
                                    return False
                                get_ready.set()
                                for _ in response.iter_bytes():
                                    pass
                                return True

                    with ThreadPoolExecutor(max_workers=calls + int(standalone_get)) as pool:
                        get_future = pool.submit(read_standalone_get) if standalone_get else None
                        if get_future is not None:
                            self.assertTrue(get_ready.wait(timeout=8))
                            self.assertFalse(get_future.done(), "GET must be open at SIGTERM")
                        futures = [
                            pool.submit(rpc, "tools/call", {
                                "name": "slow", "arguments": {"value": index},
                            }, index + 1)
                            for index in range(calls)
                        ]
                        deadline = time.monotonic() + 8
                        while not all((tmp / f"started-{index}").exists()
                                      for index in range(calls)):
                            if proc.poll() is not None or time.monotonic() >= deadline:
                                log.seek(0)
                                self.fail(f"test requests did not start:\n{log.read()}")
                            time.sleep(0.02)
                        started = time.monotonic()
                        proc.send_signal(signal.SIGTERM)
                        results = []
                        for index, future in enumerate(futures):
                            try:
                                response = future.result(timeout=14)
                                results.append(
                                    response.status_code == 200
                                    and f"complete-{index}" in response.text
                                )
                            except httpx.HTTPError:
                                results.append(False)
                        get_closed = get_future.result(timeout=12) if get_future else None
                        proc.wait(timeout=12)
                        elapsed = time.monotonic() - started
                    log.seek(0)
                    return results, elapsed, log.read(), get_closed
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)

    def test_four_finite_sse_responses_complete_on_sigterm(self):
        results, elapsed, log, get_closed = self._probe(
            calls=4, delay=2, budget=10, standalone_get=True)
        self.assertEqual(results, [True] * 4, log)
        self.assertTrue(get_closed, log)
        self.assertNotIn("ASGI callable returned without completing response", log)
        self.assertLess(elapsed, 12, log)

    def test_idle_get_does_not_exhaust_the_drain_budget(self):
        results, elapsed, log, get_closed = self._probe(
            calls=0, delay=0, budget=8, standalone_get=True)
        self.assertEqual(results, [])
        self.assertTrue(get_closed, log)
        self.assertLess(elapsed, 5, log)
        self.assertNotIn("timeout graceful shutdown exceeded", log)
        self.assertNotIn("ASGI callable returned without completing response", log)

    def test_over_budget_request_cannot_hang_shutdown(self):
        results, elapsed, log, _ = self._probe(calls=1, delay=60, budget=1)
        self.assertEqual(results, [False], log)
        self.assertLess(elapsed, 10, log)


if __name__ == "__main__":
    unittest.main()
