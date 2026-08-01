from pathlib import Path
import shutil
import subprocess
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

    def test_component_watchdogs_require_both_installed_python_assets(self) -> None:
        helper_condition = (
            "ConditionPathExists=%h/.local/libexec/grabowski/"
            "watchdog_admission_recovery.py"
        )
        script_condition = (
            "ConditionPathExists=%h/.local/libexec/grabowski/component_watchdog.py"
        )
        for unit_name in (
            "grabowski-operator-watchdog.service.example",
            "grabowski-tunnel-watchdog.service.example",
        ):
            unit = (ROOT / "systemd" / unit_name).read_text(encoding="utf-8")
            self.assertIn(script_condition, unit)
            self.assertIn(helper_condition, unit)
        docs = (ROOT / "docs" / "restart-watchdog.md").read_text(
            encoding="utf-8"
        )
        helper_position = docs.index("tools/watchdog_admission_recovery.py")
        watchdog_position = docs.index(
            "tools/component_watchdog.py", helper_position
        )
        self.assertLess(helper_position, watchdog_position)

    def test_component_watchdogs_keep_explicit_recovery_scope(self) -> None:
        operator = (
            ROOT / "systemd" / "grabowski-operator-watchdog.service.example"
        ).read_text(encoding="utf-8")
        tunnel = (
            ROOT / "systemd" / "grabowski-tunnel-watchdog.service.example"
        ).read_text(encoding="utf-8")
        self.assertIn("--component operator", operator)
        self.assertIn("--service grabowski-operator.service", operator)
        self.assertIn(
            "--tunnel-service tunnel-client-grabowski.service", operator
        )
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
        self.assertIn("OnCalendar=*-*-* *:*:00", operator)
        self.assertIn("OnCalendar=*-*-* *:0/2:30", tunnel)
        self.assertNotIn("OnUnitActiveSec=", operator)
        self.assertNotIn("OnUnitActiveSec=", tunnel)
        self.assertIn("Persistent=true", operator)
        self.assertIn("Persistent=true", tunnel)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze unavailable")
    def test_watchdog_calendar_cadences_are_accepted_by_systemd(self) -> None:
        for expression in ("*-*-* *:*:00", "*-*-* *:0/2:30"):
            with self.subTest(expression=expression):
                completed = subprocess.run(
                    ["systemd-analyze", "calendar", expression],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(
                    0,
                    completed.returncode,
                    msg=(completed.stdout + completed.stderr),
                )

    def test_component_watchdogs_are_productive_not_advisory(self) -> None:
        for name in (
            "grabowski-operator-watchdog.service.example",
            "grabowski-tunnel-watchdog.service.example",
        ):
            text = (ROOT / "systemd" / name).read_text(encoding="utf-8")
            self.assertNotIn("--check-only", text)
            self.assertIn("SuccessExitStatus=1", text)
            self.assertIn("--max-restarts 3", text)
            self.assertIn("--restart-window 900", text)
            self.assertIn("--backoff-base 60", text)
            self.assertIn("--backoff-max 900", text)
        operator = (
            ROOT / "systemd" / "grabowski-operator-watchdog.service.example"
        ).read_text(encoding="utf-8")
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", operator)
        self.assertIn("--failure-threshold 5", operator)
        self.assertIn("TimeoutStartSec=900", operator)
        self.assertNotIn("--mcp-url", operator)
        tunnel = (
            ROOT / "systemd" / "grabowski-tunnel-watchdog.service.example"
        ).read_text(encoding="utf-8")
        self.assertIn("--failure-threshold 3", tunnel)
        self.assertIn("TimeoutStartSec=90", tunnel)
        self.assertIn("SuccessExitStatus=1 5", tunnel)

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
        self.assertIn("--worktree-hygiene-repo %h/repos/grabowski", service)
        self.assertIn("--max-worktree-hygiene-actions 2", service)
        self.assertIn("--worktree-hygiene-allowed-root %h/repos/.grabowski-standalone", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ProtectHome=read-only", service)
        self.assertIn("ReadWritePaths=%h/.local/state/grabowski", service)
        self.assertIn("%h/repos/grabowski", service)
        self.assertNotIn("PrivateDevices=", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", service)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertIn("RandomizedDelaySec=30s", timer)
        self.assertIn("Persistent=true", timer)


if __name__ == "__main__":
    unittest.main()
