#!/usr/bin/env python3
"""Tooling-only WebDriver BiDi shadow matrix.

The matrix compares Chrome/WebDriver BiDi and Firefox/WebDriver BiDi against
one caller-supplied semantic observation captured from the canonical Chrome/CDP
control plane.  It owns only temporary WebDriver/browser processes.  It never
changes production routing, retry authority, browser profiles or adapters.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import time
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

try:
    import browser_bidi_shadow_benchmark_core as shadow
except ModuleNotFoundError:  # package import during tests
    from tools import browser_bidi_shadow_benchmark_core as shadow

SCHEMA_VERSION = 1
MAX_REPETITIONS = 5


def _validate_reference_receipt_sha256(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise shadow.BidiShadowError("reference receipt sha256 is invalid")
    return value


def _reference_receipt(value: str) -> str:
    try:
        return _validate_reference_receipt_sha256(value)
    except shadow.BidiShadowError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _reference(value: str) -> dict[str, Any]:
    try:
        document = json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError("reference JSON is invalid") from exc
    if not isinstance(document, dict):
        raise argparse.ArgumentTypeError("reference JSON must be an object")
    try:
        return shadow.normalize_semantic_observation(document)
    except shadow.BidiShadowError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _validate_port(port: int) -> None:
    if isinstance(port, bool) or not 1024 <= port <= 65535:
        raise shadow.BidiShadowError("benchmark port is outside the allowed range")


def build_chromedriver_argv(*, chromedriver: Path, http_port: int) -> list[str]:
    _validate_port(http_port)
    return [
        str(chromedriver),
        f"--port={http_port}",
        "--allowed-ips=127.0.0.1",
        "--verbose",
    ]


def build_chrome_session_payload(*, chrome: Path, profile: Path) -> dict[str, Any]:
    if not profile.is_absolute():
        raise shadow.BidiShadowError("Chrome benchmark profile path must be absolute")
    return {
        "capabilities": {
            "alwaysMatch": {
                "browserName": "chrome",
                "webSocketUrl": True,
                "goog:chromeOptions": {
                    "binary": str(chrome),
                    "args": [
                        "--headless=new",
                        "--disable-gpu",
                        "--no-first-run",
                        "--no-default-browser-check",
                        f"--user-data-dir={profile}",
                    ],
                },
            }
        }
    }


def validate_chrome_loopback_ws_url(value: str, *, expected_session_id: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise shadow.BidiShadowError("Chrome BiDi WebSocket URL is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "ws"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise shadow.BidiShadowError("Chrome BiDi WebSocket URL is not loopback-only")
    try:
        port = parsed.port
    except ValueError as exc:
        raise shadow.BidiShadowError("Chrome BiDi WebSocket port is invalid") from exc
    if port is None:
        raise shadow.BidiShadowError("Chrome BiDi WebSocket port is missing")
    _validate_port(port)
    if parsed.path != f"/session/{expected_session_id}":
        raise shadow.BidiShadowError("Chrome BiDi WebSocket session path does not match")
    try:
        resolved = socket.getaddrinfo(
            parsed.hostname, port, socket.AF_INET, socket.SOCK_STREAM
        )
    except OSError as exc:
        raise shadow.BidiShadowError("Chrome BiDi WebSocket host did not resolve") from exc
    addresses = {item[4][0] for item in resolved if item[4]}
    if not addresses or addresses != {"127.0.0.1"}:
        raise shadow.BidiShadowError("Chrome BiDi WebSocket host did not resolve strictly to IPv4 loopback")
    return urlunsplit(("ws", f"127.0.0.1:{port}", parsed.path, "", ""))


def parse_chrome_session_response(document: dict[str, Any]) -> dict[str, str]:
    try:
        value = document["value"]
        session_id = value["sessionId"]
        capabilities = value["capabilities"]
        websocket_url = capabilities["webSocketUrl"]
        browser_version = capabilities["browserVersion"]
        chrome_capability = capabilities["chrome"]
        driver_build = chrome_capability["chromedriverVersion"]
    except (KeyError, TypeError) as exc:
        raise shadow.BidiShadowError("Chrome WebDriver session response is incomplete") from exc
    for label, field in (
        ("session id", session_id),
        ("browser version", browser_version),
        ("ChromeDriver version", driver_build),
    ):
        if not isinstance(field, str) or not field:
            raise shadow.BidiShadowError(f"Chrome WebDriver {label} is invalid")
    safe_websocket_url = validate_chrome_loopback_ws_url(
        websocket_url, expected_session_id=session_id
    )
    return {
        "session_id": session_id,
        "websocket_url": safe_websocket_url,
        "browser_version": browser_version,
        "chromedriver_version": driver_build.split()[0],
    }


def _wait_for_driver(port: int, process: subprocess.Popen[Any], timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "not ready"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise shadow.BidiShadowError(
                f"WebDriver process exited before readiness with code {process.returncode}"
            )
        try:
            document = shadow._http_json("GET", port, "/status", timeout_seconds=0.5)
            if isinstance(document.get("value"), dict):
                return
        except (shadow.BidiShadowError, OSError) as exc:
            last_error = str(exc)
        time.sleep(0.05)
    raise shadow.BidiShadowError(f"WebDriver readiness timed out: {last_error}")


def run_chrome_bidi_once(
    *,
    chromedriver: Path,
    chrome: Path,
    http_port: int,
    work_root: Path,
    reference: dict[str, Any],
    html: str = shadow.DEFAULT_HTML,
    readiness_timeout_seconds: float = 8.0,
) -> dict[str, Any]:
    for label, executable in (("chromedriver", chromedriver), ("chrome", chrome)):
        if (
            not executable.is_absolute()
            or not executable.is_file()
            or not os.access(executable, os.X_OK)
        ):
            raise shadow.BidiShadowError(f"{label} executable is unavailable")
    if not work_root.is_absolute() or not work_root.is_dir():
        raise shadow.BidiShadowError("benchmark work root is unavailable")
    _validate_port(http_port)

    started = time.perf_counter_ns()
    session_id: str | None = None
    timings: dict[str, float] = {}
    with tempfile.TemporaryDirectory(prefix="grabowski-chrome-bidi-shadow-", dir=work_root) as temporary:
        root = Path(temporary)
        profile = root / "profile"
        profile.mkdir(mode=0o700)
        log_path = root / "chromedriver.log"
        with log_path.open("wb") as log_file:
            process = subprocess.Popen(
                build_chromedriver_argv(chromedriver=chromedriver, http_port=http_port),
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
            )
            try:
                ready_started = time.perf_counter_ns()
                _wait_for_driver(http_port, process, readiness_timeout_seconds)
                timings["driver_ready_ms"] = (time.perf_counter_ns() - ready_started) / 1_000_000

                session_started = time.perf_counter_ns()
                document = shadow._http_json(
                    "POST",
                    http_port,
                    "/session",
                    payload=build_chrome_session_payload(chrome=chrome, profile=profile),
                    timeout_seconds=readiness_timeout_seconds,
                )
                timings["session_create_ms"] = (time.perf_counter_ns() - session_started) / 1_000_000
                identity = parse_chrome_session_response(document)
                session_id = identity["session_id"]

                target_url = "data:text/html," + quote(html, safe="")
                with shadow.BidiJsonConnection(identity["websocket_url"]) as bidi:
                    tree, tree_ms = bidi.call("browsingContext.getTree", {"maxDepth": 0})
                    contexts = tree["result"].get("contexts")
                    if not isinstance(contexts, list) or len(contexts) != 1:
                        raise shadow.BidiShadowError("Chrome BiDi benchmark requires exactly one top-level context")
                    context = contexts[0].get("context")
                    if not isinstance(context, str) or not context:
                        raise shadow.BidiShadowError("Chrome BiDi browsing context is invalid")
                    navigation, navigate_ms = bidi.call(
                        "browsingContext.navigate",
                        {"context": context, "url": target_url, "wait": "complete"},
                    )
                    if navigation["result"].get("url") != target_url:
                        raise shadow.BidiShadowError("Chrome BiDi navigation readback does not match")
                    evaluation, evaluate_ms = bidi.call(
                        "script.evaluate",
                        {
                            "expression": shadow._semantic_expression(),
                            "target": {"context": context},
                            "awaitPromise": True,
                            "resultOwnership": "none",
                        },
                    )
                timings.update(
                    {"get_tree_ms": tree_ms, "navigate_ms": navigate_ms, "evaluate_ms": evaluate_ms}
                )
                observation = shadow._parse_evaluate_response(evaluation)
                parity = shadow.compare_semantics(reference, observation)
                return {
                    "schema_version": SCHEMA_VERSION,
                    "kind": "grabowski_browser_bidi_shadow_run",
                    "state": "passed" if parity["matched"] else "semantic_mismatch",
                    "transport": "webdriver-bidi",
                    "browser": {"name": "chrome", "version": identity["browser_version"]},
                    "driver": {"name": "chromedriver", "version": identity["chromedriver_version"]},
                    "binding": {
                        "http_host": "127.0.0.1",
                        "http_port": http_port,
                        "session_id_sha256": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
                    },
                    "semantic_observation": observation,
                    "parity": parity,
                    "timings_ms": {key: round(value, 3) for key, value in timings.items()},
                    "total_ms": round((time.perf_counter_ns() - started) / 1_000_000, 3),
                    "production_adapter_changed": False,
                    "retry_authorized": False,
                }
            finally:
                if session_id is not None:
                    try:
                        shadow._http_json(
                            "DELETE",
                            http_port,
                            f"/session/{session_id}",
                            timeout_seconds=3.0,
                        )
                    except Exception:
                        pass
                shadow._terminate_process_group(process)


def _summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    if not runs:
        raise shadow.BidiShadowError("matrix backend has no runs")
    totals = [float(run["total_ms"]) for run in runs]
    sessions = [float(run["timings_ms"]["session_create_ms"]) for run in runs]
    return {
        "runs": len(runs),
        "passed": sum(run.get("state") == "passed" for run in runs),
        "total_ms": {
            "min": round(min(totals), 3),
            "median": round(statistics.median(totals), 3),
            "max": round(max(totals), 3),
        },
        "session_create_ms": {
            "min": round(min(sessions), 3),
            "median": round(statistics.median(sessions), 3),
            "max": round(max(sessions), 3),
        },
    }


def run_shadow_matrix(
    *,
    chromedriver: Path,
    chrome: Path,
    geckodriver: Path,
    firefox: Path,
    chrome_http_port: int,
    firefox_http_port: int,
    firefox_websocket_port: int,
    work_root: Path,
    reference: dict[str, Any],
    reference_receipt_sha256: str,
    repetitions: int = 3,
    html: str = shadow.DEFAULT_HTML,
) -> dict[str, Any]:
    if isinstance(repetitions, bool) or not 1 <= repetitions <= MAX_REPETITIONS:
        raise shadow.BidiShadowError(f"repetitions must be between 1 and {MAX_REPETITIONS}")
    reference = shadow.normalize_semantic_observation(reference)
    reference_receipt_sha256 = _validate_reference_receipt_sha256(
        reference_receipt_sha256
    )
    base_ports = {chrome_http_port, firefox_http_port, firefox_websocket_port}
    if len(base_ports) != 3:
        raise shadow.BidiShadowError("matrix base ports must be distinct")
    for port in base_ports:
        _validate_port(port)
    chrome_runs: list[dict[str, Any]] = []
    firefox_runs: list[dict[str, Any]] = []
    for index in range(repetitions):
        chrome_port = chrome_http_port + index
        firefox_port = firefox_http_port + index * 2
        firefox_ws_port = firefox_websocket_port + index * 2
        effective = {chrome_port, firefox_port, firefox_ws_port}
        if len(effective) != 3:
            raise shadow.BidiShadowError("matrix effective ports overlap")
        for port in effective:
            _validate_port(port)
        chrome_report = run_chrome_bidi_once(
            chromedriver=chromedriver,
            chrome=chrome,
            http_port=chrome_port,
            work_root=work_root,
            reference=reference,
            html=html,
        )
        firefox_report = shadow.run_shadow_benchmark(
            geckodriver=geckodriver,
            firefox=firefox,
            http_port=firefox_port,
            websocket_port=firefox_ws_port,
            work_root=work_root,
            reference=reference,
            html=html,
        )
        if chrome_report.get("state") != "passed" or firefox_report.get("state") != "passed":
            raise shadow.BidiShadowError("one or more BiDi shadow runs did not match the semantic reference")
        chrome_runs.append(chrome_report)
        firefox_runs.append(firefox_report)
    semantic_sha256 = shadow.compare_semantics(reference, reference)["reference_sha256"]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_browser_bidi_shadow_matrix",
        "state": "passed",
        "reference": {
            "transport": "chrome-cdp",
            "source": "external-receipt-bound",
            "receipt_sha256": reference_receipt_sha256,
            "semantic_sha256": semantic_sha256,
        },
        "repetitions": repetitions,
        "backends": {
            "chrome_webdriver_bidi": {"runs": chrome_runs, "summary": _summary(chrome_runs)},
            "firefox_webdriver_bidi": {"runs": firefox_runs, "summary": _summary(firefox_runs)},
        },
        "production_adapter_changed": False,
        "retry_authorized": False,
        "timing_comparison_is_advisory": True,
        "does_not_establish": [
            "semantic_reference_receipt_correspondence_without_external_verifier",
            "production_backend_promotion",
            "performance_superiority",
            "external_effect_correctness",
            "permission_to_replace_chrome_cdp",
        ],
    }


def failure_report(exc: BaseException) -> dict[str, Any]:
    report = shadow.failure_report(exc)
    return {**report, "kind": "grabowski_browser_bidi_shadow_matrix"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare Chrome and Firefox WebDriver BiDi against one caller-bound Chrome/CDP semantic reference."
    )
    parser.add_argument("--chromedriver", type=Path, required=True)
    parser.add_argument("--chrome", type=Path, required=True)
    parser.add_argument("--geckodriver", type=Path, required=True)
    parser.add_argument("--firefox", type=Path, required=True)
    parser.add_argument("--chrome-http-port", type=int, required=True)
    parser.add_argument("--firefox-http-port", type=int, required=True)
    parser.add_argument("--firefox-websocket-port", type=int, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--reference-json", type=_reference, required=True)
    parser.add_argument(
        "--reference-receipt-sha256", type=_reference_receipt, required=True
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--html", default=shadow.DEFAULT_HTML)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if len(args.html.encode("utf-8")) > 64 * 1024:
        report = failure_report(shadow.BidiShadowError("benchmark HTML exceeds 64 KiB"))
    else:
        try:
            report = run_shadow_matrix(
                chromedriver=args.chromedriver,
                chrome=args.chrome,
                geckodriver=args.geckodriver,
                firefox=args.firefox,
                chrome_http_port=args.chrome_http_port,
                firefox_http_port=args.firefox_http_port,
                firefox_websocket_port=args.firefox_websocket_port,
                work_root=args.work_root,
                reference=args.reference_json,
                reference_receipt_sha256=args.reference_receipt_sha256,
                repetitions=args.repetitions,
                html=args.html,
            )
        except Exception as exc:
            report = failure_report(exc)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("state") == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
