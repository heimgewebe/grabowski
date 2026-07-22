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

    def test_tunnel_restart_follows_operator_without_failure_binding(self) -> None:
        text = (
            ROOT
            / "systemd"
            / "tunnel-client-grabowski.service.d"
            / "70-operator-dependency.conf.example"
        ).read_text(encoding="utf-8")
        self.assertIn("Wants=grabowski-operator.service", text)
        self.assertIn("After=grabowski-operator.service", text)
        self.assertIn("PartOf=grabowski-operator.service", text)
        self.assertNotIn("BindsTo=", text)

    def test_watchdog_cadence_matches_probe_cost(self) -> None:
        operator = (
            ROOT / "systemd" / "grabowski-operator-watchdog.timer.example"
        ).read_text(encoding="utf-8")
        tunnel = (
            ROOT / "systemd" / "grabowski-tunnel-watchdog.timer.example"
        ).read_text(encoding="utf-8")
        self.assertIn("OnUnitActiveSec=60s", operator)
        self.assertIn("OnUnitActiveSec=30s", tunnel)
        self.assertIn("Persistent=true", operator)
        self.assertIn("Persistent=true", tunnel)

    def test_component_watchdogs_are_productive_not_advisory(self) -> None:
        for name in (
            "grabowski-operator-watchdog.service.example",
            "grabowski-tunnel-watchdog.service.example",
        ):
            text = (ROOT / "systemd" / name).read_text(encoding="utf-8")
            self.assertNotIn("--check-only", text)
            self.assertIn("SuccessExitStatus=1", text)
            self.assertIn("TimeoutStartSec=90", text)
            self.assertIn("--max-restarts 3", text)
            self.assertIn("--restart-window 900", text)
            self.assertIn("--backoff-base 60", text)
            self.assertIn("--backoff-max 900", text)
        operator = (
            ROOT / "systemd" / "grabowski-operator-watchdog.service.example"
        ).read_text(encoding="utf-8")
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", operator)
        self.assertIn("--failure-threshold 2", operator)
        self.assertNotIn("--mcp-url", operator)
        tunnel = (
            ROOT / "systemd" / "grabowski-tunnel-watchdog.service.example"
        ).read_text(encoding="utf-8")
        self.assertIn("--failure-threshold 3", tunnel)

    def test_timers_keep_decorrelation_while_watchdog_owns_backoff(self) -> None:
        for name in (
            "grabowski-operator-watchdog.timer.example",
            "grabowski-tunnel-watchdog.timer.example",
        ):
            text = (ROOT / "systemd" / name).read_text(encoding="utf-8")
            self.assertIn("RandomizedDelaySec=3s", text)
            # systemd 249 has no RestartSteps; backoff lives in the watchdog.
            self.assertNotIn("RestartSteps", "".join(
                line for line in text.splitlines() if not line.startswith("#")
            ))

    def test_runtime_retention_timer_uses_release_bound_hash_guarded_tool(self) -> None:
        service = (
            ROOT / "systemd" / "grabowski-runtime-retention.service.example"
        ).read_text(encoding="utf-8")
        timer = (
            ROOT / "systemd" / "grabowski-runtime-retention.timer.example"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "%h/.local/share/grabowski-mcp/tools/maintain_runtime_state.py",
            service,
        )
        self.assertIn("--periodic-apply", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ProtectHome=read-only", service)
        self.assertIn("ReadWritePaths=%h/.local/state/grabowski", service)
        self.assertNotIn("PrivateDevices=", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", service)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertIn("RandomizedDelaySec=30s", timer)
        self.assertIn("Persistent=true", timer)


if __name__ == "__main__":
    unittest.main()
