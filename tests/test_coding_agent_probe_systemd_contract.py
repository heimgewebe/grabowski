from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "systemd"


class CodingAgentProbeSystemdContractTests(unittest.TestCase):
    def test_service_is_metadata_only_hardened_and_state_scoped(self) -> None:
        unit = (SYSTEMD / "grabowski-coding-agent-probe.service.example").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "ExecStart=%h/.local/libexec/grabowski/coding_agent_probe_scheduler.py",
            unit,
        )
        self.assertIn("ConditionPathExists=%h/bin/agent-route", unit)
        self.assertIn(
            "ConditionPathExists=%h/.config/grabowski/coding-agent-probe-scheduler-router.sha256",
            unit,
        )
        self.assertNotIn("coding-agent-catalog.json", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ProtectHome=read-only", unit)
        self.assertIn("MemoryMax=512M", unit)
        self.assertIn("TasksMax=50", unit)
        self.assertIn(
            "ReadWritePaths=%h/.local/state/grabowski/coding-agent-router",
            unit,
        )
        for variable in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "XAI_API_KEY",
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
            "OPENROUTER_API_KEY",
            "AZURE_OPENAI_API_KEY",
        ):
            self.assertIn(f"Environment={variable}=", unit)
        self.assertNotIn("agent-route recommend", unit)
        self.assertNotIn("agent-route observe", unit)

    def test_user_service_avoids_capability_mutating_hardening(self) -> None:
        unit = (SYSTEMD / "grabowski-coding-agent-probe.service.example").read_text(
            encoding="utf-8"
        )
        # On the supported heim-pc user manager these directives terminate before
        # ExecStart with status 218/CAPABILITIES. The remaining sandbox controls
        # still provide read-only home/system access and a scoped writable state dir.
        for incompatible_directive in (
            "PrivateDevices=yes",
            "ProtectKernelModules=yes",
            "ProtectKernelLogs=yes",
        ):
            self.assertNotIn(incompatible_directive, unit)
        for compatible_directive in (
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "ProtectKernelTunables=yes",
            "ProtectControlGroups=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "RestrictRealtime=yes",
        ):
            self.assertIn(compatible_directive, unit)

    def test_timer_refreshes_inside_the_one_hour_freshness_window(self) -> None:
        timer = (SYSTEMD / "grabowski-coding-agent-probe.timer.example").read_text(
            encoding="utf-8"
        )
        self.assertIn("OnUnitActiveSec=45min", timer)
        self.assertIn("RandomizedDelaySec=3min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("Unit=grabowski-coding-agent-probe.service", timer)


if __name__ == "__main__":
    unittest.main()
