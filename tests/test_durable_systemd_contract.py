from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DurableSystemdContractTests(unittest.TestCase):
    def test_operator_unit_is_loopback_only_and_independent(self) -> None:
        text = (
            ROOT / "systemd" / "grabowski-operator.service.example"
        ).read_text(encoding="utf-8")
        self.assertIn("grabowski_operator --transport streamable-http", text)
        self.assertIn("--host 127.0.0.1 --port 18181", text)
        self.assertIn("Restart=on-failure", text)
        self.assertIn("KillMode=mixed", text)
        self.assertNotIn("tunnel-client", text)

    def test_component_watchdogs_restart_only_their_service(self) -> None:
        operator = (
            ROOT / "systemd" / "grabowski-operator-watchdog.service.example"
        ).read_text(encoding="utf-8")
        tunnel = (
            ROOT / "systemd" / "grabowski-tunnel-watchdog.service.example"
        ).read_text(encoding="utf-8")
        self.assertIn("--component operator", operator)
        self.assertIn("--service grabowski-operator.service", operator)
        self.assertNotIn("tunnel-client-grabowski.service", operator)
        self.assertIn("--component tunnel", tunnel)
        self.assertIn("--service tunnel-client-grabowski.service", tunnel)
        self.assertNotIn("grabowski-operator.service", tunnel)

    def test_tunnel_dependency_is_non_binding(self) -> None:
        text = (
            ROOT
            / "systemd"
            / "tunnel-client-grabowski.service.d"
            / "70-operator-dependency.conf.example"
        ).read_text(encoding="utf-8")
        self.assertIn("Wants=grabowski-operator.service", text)
        self.assertIn("After=grabowski-operator.service", text)
        self.assertNotIn("BindsTo=", text)
        self.assertNotIn("PartOf=", text)

    def test_watchdogs_run_every_thirty_seconds(self) -> None:
        for name in (
            "grabowski-operator-watchdog.timer.example",
            "grabowski-tunnel-watchdog.timer.example",
        ):
            text = (ROOT / "systemd" / name).read_text(encoding="utf-8")
            self.assertIn("OnUnitActiveSec=30s", text)
            self.assertIn("Persistent=true", text)


if __name__ == "__main__":
    unittest.main()
