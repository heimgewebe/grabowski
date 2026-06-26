from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import deploy_runtime as core
import deploy_runtime_dual as dual

RUNTIME = Path("/home/alex/.local/share/grabowski-mcp")
BASE = "http" + "://" + "127.0.0.1"


class UrlBindingTests(unittest.TestCase):
    def topology(self, urls):
        payload = {"mcp": {"server_urls": urls}}
        with mock.patch.object(dual, "_load_yaml", return_value=payload):
            return dual.profile_topology(Path("profile.yaml"), RUNTIME)

    def test_exact_loopback_endpoint_is_required(self) -> None:
        valid = BASE + ":18181/mcp"
        self.assertEqual(self.topology([{"url": valid}]).kind, "url")
        invalid = [
            "http" + "://" + "localhost:18181/mcp",
            BASE + ":9999/mcp",
            "https" + "://" + "127.0.0.1:18181/mcp",
            BASE + ":18181/other",
            "http" + "://" + "user@127.0.0.1:18181/mcp",
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(core.DeployError):
                    self.topology([{"url": value}])

    def test_exactly_one_endpoint_is_required(self) -> None:
        valid = {"url": BASE + ":18181/mcp"}
        for values in ([], [valid, valid]):
            with self.subTest(values=values):
                with self.assertRaises(core.DeployError):
                    self.topology(values)


class RollbackReturnContractTests(unittest.TestCase):
    def test_restore_pointer_may_successfully_return_none(self) -> None:
        contract = core.load_contract(ROOT / "config" / "runtime-entrypoint.json")
        inactive = core.ServiceObservation(True, "loaded", "inactive", "dead", 0, 0)
        active = core.ServiceObservation(True, "loaded", "active", "running", 123, 0)
        ready = dual.DualReadiness(True, active, active, "live", "ready")
        activation = type("Activation", (), {"runtime": RUNTIME, "previous": object()})()
        events = []
        with (
            mock.patch.object(dual, "stop_service", side_effect=lambda unit: events.append("stop:" + unit) or inactive),
            mock.patch.object(core, "restore_pointer", side_effect=lambda value: events.append("restore") or None),
            mock.patch.object(core, "verify_pointer_state", side_effect=lambda *args: events.append("verify-pointer") or object()),
            mock.patch.object(dual, "start_service", side_effect=lambda unit: events.append("start:" + unit) or active),
            mock.patch.object(dual, "verify_operator_process", return_value={"pid": 1}),
            mock.patch.object(dual, "wait_until_ready", return_value=ready),
        ):
            with self.assertRaises(core.DeployError) as caught:
                dual.rollback_url(core.DeployError("primary"), activation=activation, contract=contract, timeout_seconds=1)
        self.assertIn('"pointer_restore": "restored"', str(caught.exception))
        self.assertIn("start:" + dual.OPERATOR_SERVICE, events)
        self.assertIn("start:" + dual.TUNNEL_SERVICE, events)


if __name__ == "__main__":
    unittest.main()
