from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_browser_diagnostics as diagnostics


TEST_WORKER_STATE = Path("/tmp/grabowski-browser-diagnostics-test-workers")
diagnostics.operator = mock.Mock(HOME=Path("/tmp"))
diagnostics.resources = mock.Mock()
diagnostics.workers = mock.Mock(WORKER_STATE=TEST_WORKER_STATE)


EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def worker_record() -> dict[str, object]:
    root = diagnostics.workers.WORKER_STATE / "instances" / "0123456789abcdefabcd"
    return {
        "worker_id": "0123456789abcdefabcd",
        "kind": "browser",
        "unit": "grabowski-browser-worker-0123456789abcdefabcd.service",
        "state": "running",
        "executable": "/opt/google/chrome/google-chrome",
        "port": 45780,
        "profile_path": str(diagnostics.workers.WORKER_STATE / "profiles" / "0123456789abcdefabcd"),
        "config_path": str(root / "worker.json"),
        "created_at_unix": 1000,
        "lease_keys_json": json.dumps(
            [
                "port:45780",
                f"browser-profile:{diagnostics.workers.WORKER_STATE / 'profiles' / '0123456789abcdefabcd'}",
            ]
        ),
    }


def node_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "ok": True,
        "result_code": "ok",
        "target": {
            "url": {
                "scheme": "https",
                "host_sha256": "a" * 64,
                "path_sha256": "b" * 64,
                "query_present": True,
                "fragment_present": False,
                "raw_url": "https://secret.invalid/?token=secret",
            }
        },
        "console": [
            {
                "source": "runtime",
                "level": "error",
                "text_sha256": "c" * 64,
                "text_bytes": 27,
                "raw_text": "password=do-not-return",
                "arguments": [
                    {
                        "type": "string",
                        "subtype": "",
                        "class_name": "",
                        "value_sha256": "d" * 64,
                        "value_bytes": 20,
                        "value": "do-not-return",
                    }
                ],
                "location": {
                    "url": {
                        "scheme": "https",
                        "host_sha256": "e" * 64,
                        "path_sha256": "f" * 64,
                        "query_present": False,
                        "fragment_present": False,
                    },
                    "line_number": 4,
                    "column_number": 8,
                },
            }
        ],
        "network": [
            {
                "request_id_sha256": "1" * 64,
                "method": "POST",
                "resource_type": "Fetch",
                "initiator_type": "script",
                "url": {
                    "scheme": "https",
                    "host_sha256": "2" * 64,
                    "path_sha256": "3" * 64,
                    "query_present": True,
                    "fragment_present": False,
                },
                "has_post_data": True,
                "status": 204,
                "mime_type": "text/plain",
                "protocol": "h2",
                "from_disk_cache": False,
                "from_service_worker": False,
                "headers": {"authorization": "secret"},
                "post_data": "secret-body",
            }
        ],
    }


class BrowserDiagnosticsContractTests(unittest.TestCase):
    def test_node_source_contains_no_page_effect_methods(self) -> None:
        forbidden = [
            "Page.navigate",
            "Page.reload",
            "Runtime.evaluate",
            "Runtime.callFunctionOn",
            "DOM.set",
            "Input.dispatch",
            "Page.captureScreenshot",
            "Network.getResponseBody",
            "Network.getRequestPostData",
            "Network.setCacheDisabled",
        ]
        for method in forbidden:
            self.assertNotIn(method, diagnostics.NODE_SOURCE)
        self.assertIn("Runtime.enable", diagnostics.NODE_SOURCE)
        self.assertIn("Log.enable", diagnostics.NODE_SOURCE)
        self.assertIn("Network.enable", diagnostics.NODE_SOURCE)

    def test_capture_bounds_are_fail_closed(self) -> None:
        for invalid in (False, 99, 5001, 1.5):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    diagnostics._checked_capture_ms(invalid)
        for invalid in (False, 0, 51, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    diagnostics._checked_max_events(invalid)

    def test_normalizer_strips_unknown_raw_sensitive_fields(self) -> None:
        normalized = diagnostics._normalize_node_payload(node_payload(), max_events=20)
        rendered = json.dumps(normalized, sort_keys=True)
        self.assertNotIn("do-not-return", rendered)
        self.assertNotIn("secret.invalid", rendered)
        self.assertNotIn("authorization", rendered)
        self.assertNotIn("secret-body", rendered)
        self.assertNotIn("raw_text", rendered)
        self.assertNotIn("raw_url", rendered)
        self.assertEqual(normalized["console"][0]["text_sha256"], "c" * 64)
        self.assertEqual(normalized["network"][0]["status"], 204)
        self.assertTrue(normalized["network"][0]["url"]["query_present"])

    def test_invalid_hashes_collapse_to_empty_digest(self) -> None:
        normalized = diagnostics._normalize_node_payload(
            {
                "schema_version": 1,
                "ok": True,
                "result_code": "ok",
                "target": {"url": {"host_sha256": "raw-host", "path_sha256": "raw-path"}},
                "console": [],
                "network": [],
            },
            max_events=1,
        )
        self.assertEqual(normalized["target"]["url"]["host_sha256"], EMPTY_HASH)
        self.assertEqual(normalized["target"]["url"]["path_sha256"], EMPTY_HASH)

    def test_failure_report_never_grants_retry_or_actions(self) -> None:
        report = diagnostics.failure_report(diagnostics.BrowserDiagnosticsError("worker-not-running"))
        self.assertEqual(report["state"], "failed_closed")
        self.assertTrue(report["read_only"])
        self.assertFalse(report["page_effects"])
        self.assertFalse(report["production_adapter_changed"])
        self.assertFalse(report["retry_authorized"])

    def test_cli_bootstraps_repository_src_path(self) -> None:
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, str(root / "tools/browser_diagnostics.py"), "--help"],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Passively collect bounded diagnostics", result.stdout)


class BrowserDiagnosticsWorkerBindingTests(unittest.TestCase):
    def _lease(self, key: str, owner: str) -> dict[str, object]:
        return {
            "resource_key": key,
            "owner_id": owner,
            "expires_at_unix": 20_000,
        }

    def test_live_binding_requires_running_systemd_and_owner_leases(self) -> None:
        record = worker_record()
        owner = f"worker:{record['worker_id']}"
        with (
            mock.patch.object(diagnostics.workers, "_row", return_value=record),
            mock.patch.object(
                diagnostics.workers, "_observe", return_value={"state": "running"}
            ),
            mock.patch.object(diagnostics.workers, "_now", return_value=10_000),
            mock.patch.object(
                diagnostics.resources,
                "inspect_resource",
                side_effect=lambda key: self._lease(key, owner),
            ),
        ):
            observed, digest = diagnostics._live_worker_record(
                str(record["worker_id"]), min_remaining_seconds=10
            )
        self.assertEqual(observed, record)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_terminal_systemd_observation_rejects_before_cdp(self) -> None:
        record = worker_record()
        with (
            mock.patch.object(diagnostics.workers, "_row", return_value=record),
            mock.patch.object(
                diagnostics.workers, "_observe", return_value={"state": "completed"}
            ),
        ):
            with self.assertRaisesRegex(diagnostics.BrowserDiagnosticsError, "worker-not-running"):
                diagnostics._live_worker_record(str(record["worker_id"]), min_remaining_seconds=10)

    def test_foreign_lease_rejects_before_cdp(self) -> None:
        record = worker_record()
        with (
            mock.patch.object(diagnostics.workers, "_row", return_value=record),
            mock.patch.object(
                diagnostics.workers, "_observe", return_value={"state": "running"}
            ),
            mock.patch.object(diagnostics.workers, "_now", return_value=10_000),
            mock.patch.object(
                diagnostics.resources,
                "inspect_resource",
                return_value={"owner_id": "worker:foreign", "expires_at_unix": 20_000},
            ),
        ):
            with self.assertRaisesRegex(diagnostics.BrowserDiagnosticsError, "worker-lease"):
                diagnostics._live_worker_record(str(record["worker_id"]), min_remaining_seconds=10)

    def test_expiring_lease_rejects_before_cdp(self) -> None:
        record = worker_record()
        owner = f"worker:{record['worker_id']}"
        with (
            mock.patch.object(diagnostics.workers, "_row", return_value=record),
            mock.patch.object(
                diagnostics.workers, "_observe", return_value={"state": "running"}
            ),
            mock.patch.object(diagnostics.workers, "_now", return_value=10_000),
            mock.patch.object(
                diagnostics.resources,
                "inspect_resource",
                return_value={"owner_id": owner, "expires_at_unix": 10_001},
            ),
        ):
            with self.assertRaisesRegex(diagnostics.BrowserDiagnosticsError, "worker-lease"):
                diagnostics._live_worker_record(str(record["worker_id"]), min_remaining_seconds=10)

    def test_config_path_must_match_exact_worker_instance(self) -> None:
        record = worker_record()
        record["config_path"] = str(
            diagnostics.workers.WORKER_STATE / "instances" / "foreign" / "worker.json"
        )
        with mock.patch.object(diagnostics.workers, "_row", return_value=record):
            with self.assertRaisesRegex(diagnostics.BrowserDiagnosticsError, "worker-binding"):
                diagnostics._live_worker_record(str(record["worker_id"]), min_remaining_seconds=10)

    def test_lease_keys_must_match_exact_worker_resources(self) -> None:
        record = worker_record()
        record["lease_keys_json"] = json.dumps(["port:45780", "component:unexpected"])
        with (
            mock.patch.object(diagnostics.workers, "_row", return_value=record),
            mock.patch.object(
                diagnostics.workers, "_observe", return_value={"state": "running"}
            ),
            mock.patch.object(diagnostics.workers, "_now", return_value=10_000),
            mock.patch.object(diagnostics.resources, "inspect_resource") as inspect_resource,
        ):
            with self.assertRaisesRegex(diagnostics.BrowserDiagnosticsError, "worker-lease"):
                diagnostics._live_worker_record(str(record["worker_id"]), min_remaining_seconds=10)
        inspect_resource.assert_not_called()


class BrowserDiagnosticsRunTests(unittest.TestCase):
    def test_node_runner_exposes_only_managed_port_and_bounded_controls(self) -> None:
        record = worker_record()
        payload = node_payload()
        execution = {
            "returncode": 0,
            "stdout": json.dumps(payload) + "\n",
            "stderr": "",
        }
        with (
            mock.patch.object(diagnostics, "_node_executable", return_value=Path("/usr/bin/node")),
            mock.patch.object(diagnostics.operator, "_run", return_value=execution) as run,
        ):
            observed = diagnostics._run_node_capture(record, capture_ms=250, max_events=3)
        argv = run.call_args.args[0]
        request = json.loads(argv[-1])
        self.assertEqual(request["port"], record["port"])
        self.assertEqual(request["capture_ms"], 250)
        self.assertEqual(request["max_events"], 3)
        self.assertNotIn("profile_path", request)
        self.assertNotIn("endpoint", request)
        self.assertNotIn("url", request)
        self.assertEqual(observed["network"][0]["method"], "POST")

    def test_observe_rechecks_worker_after_capture_and_returns_bounded_report(self) -> None:
        record = worker_record()
        identity = diagnostics._sha256_json(diagnostics._worker_identity(record))
        capture = diagnostics._normalize_node_payload(node_payload(), max_events=20)
        with (
            mock.patch.object(
                diagnostics,
                "_live_worker_record",
                side_effect=[(record, identity), (record, identity)],
            ) as live,
            mock.patch.object(diagnostics, "_run_node_capture", return_value=capture),
        ):
            report = diagnostics.observe_browser_diagnostics(
                str(record["worker_id"]), capture_ms=250, max_events=5
            )
        self.assertEqual(live.call_count, 2)
        self.assertEqual(report["state"], "observed")
        self.assertTrue(report["read_only"])
        self.assertFalse(report["page_effects"])
        self.assertFalse(report["retry_authorized"])
        self.assertEqual(report["screenshot"]["state"], "not_implemented")
        self.assertEqual(report["console"]["count"], 1)
        self.assertEqual(report["network"]["count"], 1)

    def test_post_capture_worker_identity_drift_discards_diagnostics(self) -> None:
        record = worker_record()
        with (
            mock.patch.object(
                diagnostics,
                "_live_worker_record",
                side_effect=[(record, "a" * 64), (record, "b" * 64)],
            ),
            mock.patch.object(
                diagnostics,
                "_run_node_capture",
                return_value=diagnostics._normalize_node_payload(node_payload(), max_events=5),
            ),
        ):
            with self.assertRaisesRegex(diagnostics.BrowserDiagnosticsError, "worker-changed"):
                diagnostics.observe_browser_diagnostics(
                    str(record["worker_id"]), capture_ms=250, max_events=5
                )


if __name__ == "__main__":
    unittest.main()
