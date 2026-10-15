"""Exact tests for the no-provider root-systemd launcher and future live plan."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import repobrief_agent_benchmark_systemd_launcher as launcher


class RootSystemdLauncherTests(unittest.TestCase):
    @staticmethod
    def props(argv: list[str]) -> dict[str, str]:
        values = [
            value.removeprefix("--property=")
            for value in argv
            if value.startswith("--property=")
        ]
        results = {}
        for item in values:
            key, _, value = item.partition("=")
            if key in results:
                raise AssertionError("duplicate property " + key)
            results[key] = value
        return results

    def test_service_id_is_bounded_and_cannot_inject_unit_or_paths(self) -> None:
        for identifier in ("test", "test-2", "a" * 17):
            self.assertEqual(
                launcher.service_name(identifier), "grabowski-rab-" + identifier
            )
        for invalid in (
            "",
            "Test",
            "2test",
            "-test",
            "test/a",
            "test..",
            "test@.service",
            "test\n--property=DevicePolicy=auto",
            "a" * 18,
            "a" * 25,
            "ä",
        ):
            with self.subTest(value=invalid):
                with self.assertRaises(launcher.LauncherError):
                    launcher.service_name(invalid)

    def test_probe_command_is_exact_root_systemd_and_not_provider(self) -> None:
        cmd = launcher.probe_argv("test-one")
        self.assertEqual(cmd[0], "/usr/bin/systemd-run")
        self.assertEqual(cmd[1:5], ["--system", "--wait", "--pipe", "--collect"])
        self.assertIn("--unit=grabowski-rab-test-one", cmd)
        self.assertEqual(cmd[cmd.index("--") + 1], "/usr/bin/python3")
        self.assertEqual(cmd[cmd.index("--") + 2], "-c")
        self.assertNotIn("--allow-live-provider", cmd)
        self.assertFalse(any("codex" in x.lower() for x in cmd))

    def test_probe_private_mounts_are_runtime_owned_and_closed(self) -> None:
        p = self.props(launcher.probe_argv("proof"))
        self.assertEqual(p["DynamicUser"], "yes")
        self.assertEqual(p["User"], "grabowski-rab-proof")
        self.assertEqual(p["Group"], "grabowski-rab-proof")
        for key, expected in (
            ("PrivateDevices", "yes"),
            ("DevicePolicy", "closed"),
            ("PrivateTmp", "yes"),
            ("PrivateIPC", "yes"),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("Delegate", "no"),
            ("ProtectKernelTunables", "yes"),
            ("ProtectKernelModules", "yes"),
            ("ProtectKernelLogs", "yes"),
            ("ProtectControlGroups", "yes"),
        ):
            self.assertEqual(p[key], expected)
        self.assertEqual(p["CapabilityBoundingSet"], "")
        self.assertEqual(p["AmbientCapabilities"], "")
        self.assertEqual(p["TemporaryFileSystem"], launcher._TMPFS_SHM)
        self.assertEqual(p["RuntimeDirectoryMode"], "0700")
        self.assertEqual(
            p["InaccessiblePaths"].split(),
            [
                "/run/user",
                "/run/docker",
                "/mnt/backup",
                "/dev/hugepages",
                "/var/lib/private",
            ],
        )
        self.assertNotIn("StateDirectory", p)
        self.assertNotIn("StateDirectoryMode", p)

    def test_probe_only_four_writable_output_leaves(self) -> None:
        p = self.props(launcher.probe_argv("proof"))
        home = "/run/grabowski-rab-proof-home"
        self.assertEqual(p["Environment"], "HOME=" + home)
        self.assertEqual(
            p["ReadWritePaths"].split(),
            [home + "/epoch/" + leaf for leaf in launcher._OUTPUTS],
        )
        self.assertEqual(
            p["ReadOnlyPaths"].split(),
            [
                "/run",
                "/run/grabowski-rab-proof-tmp",
                "/run/grabowski-rab-proof-var",
                home,
                home + "/repos",
                "/proc",
                "/sys",
            ],
        )
        self.assertEqual(
            p["BindPaths"].split(),
            [
                "/run/grabowski-rab-proof-tmp:/tmp",
                "/run/grabowski-rab-proof-var:/var/tmp",
            ],
        )
        self.assertIn("grabowski-rab-proof-home/repos", p["RuntimeDirectory"].split())
        for leaf in launcher._OUTPUTS:
            self.assertIn(
                f"grabowski-rab-proof-home/epoch/{leaf}",
                p["RuntimeDirectory"].split(),
            )

    def test_no_host_shared_dev_shm_mount_alias(self) -> None:
        for mode in (True, False):
            with self.subTest(probe=mode):
                cmd = launcher.unit_argv("safe", ["/usr/bin/true"], probe=mode)
                p = self.props(cmd)
                self.assertNotIn("/dev/shm:/tmp", p["BindPaths"])
                self.assertNotIn("/dev/shm:/var/tmp", p["BindPaths"])
                self.assertNotIn("/tmp:rw", p.get("TemporaryFileSystem", ""))
                self.assertNotIn("/var/tmp:rw", p.get("TemporaryFileSystem", ""))

    def test_probe_denies_any_additional_writable_kernel_mount(self) -> None:
        # The probe must not merely check its HOME subtree. The same host
        # previously exposed RW /run/user, Docker and autofs mounts.
        program = launcher._PROBE_PROGRAM
        self.assertIn('allowed_rw.update(("/tmp", "/var/tmp"', program)
        self.assertIn("if actual_rw != allowed_rw:", program)
        self.assertIn("unexpected writable mount(s)", program)
        self.assertIn('"only_expected_rw_mounts": len(actual_rw)', program)

    def test_live_plan_uses_proven_physical_state_root_binding(self) -> None:
        cmd = launcher.live_runner_plan(
            "live",
            Path("/usr/local/libexec/repobrief_agent_benchmark_codex_runner.py"),
            Path("/var/lib/frozen/requests"),
            Path("/var/lib/frozen/map.json"),
            Path("/usr/local/bin/codex"),
            "a" * 64,
        )
        p = self.props(cmd)
        self.assertIn("/var/lib/private", p["InaccessiblePaths"].split())
        home = "/var/lib/grabowski-rab-live"
        self.assertEqual(p["Environment"], "HOME=" + home)
        self.assertEqual(
            p["BindPaths"].split(),
            [
                "/run/grabowski-rab-live-tmp:/tmp",
                "/run/grabowski-rab-live-var:/var/tmp",
                "/var/lib/private/grabowski-rab-live:" + home,
            ],
        )
        self.assertEqual(
            p["ReadOnlyPaths"].split(),
            [
                "/run",
                "/run/grabowski-rab-live-tmp",
                "/run/grabowski-rab-live-var",
                home,
                home + "/repos",
                "/proc",
                "/sys",
            ],
        )
        self.assertEqual(
            p["ReadWritePaths"].split(),
            [home + "/epoch/" + leaf for leaf in launcher._OUTPUTS],
        )
        self.assertEqual(p["StateDirectoryMode"], "0700")
        self.assertEqual(
            p["StateDirectory"].split(),
            ["grabowski-rab-live/epoch/" + leaf for leaf in launcher._OUTPUTS]
            + ["grabowski-rab-live/repos"],
        )
        self.assertNotIn("--collect", cmd)
        self.assertIn("--codex-command-sha256", cmd)
        self.assertNotIn("--allow-live-provider", cmd)

    def test_live_plan_provider_optin_does_not_start_any_process(self) -> None:
        with patch.object(subprocess, "run") as subprocess_run:
            cmd = launcher.live_runner_plan(
                "candidate",
                Path("/usr/lib/repobrief_agent_benchmark_codex_runner.py"),
                Path("/requests"),
                Path("/repo.json"),
                Path("/usr/bin/codex"),
                "b" * 64,
                allow_live_provider=True,
            )
            self.assertIn("--allow-live-provider", cmd)
            subprocess_run.assert_not_called()

    def test_live_plan_rejects_invalid_input_paths_and_identity(self) -> None:
        params = dict(
            run_id="candidate",
            runner=Path("/usr/lib/repobrief_agent_benchmark_codex_runner.py"),
            request_root=Path("/requests"),
            repository_map=Path("/map.json"),
            codex=Path("/usr/bin/codex"),
            codex_sha256="a" * 64,
        )
        for change in (
            {"runner": Path("/tmp/unknown_runner.py")},
            {"runner": Path("relative/repobrief_agent_benchmark_codex_runner.py")},
            {"request_root": Path("/tmp/../etc")},
            {"repository_map": Path("../repo.json")},
            {"codex": Path("codex")},
            {"codex_sha256": "a" * 63},
            {"codex_sha256": "g" * 64},
        ):
            with self.subTest(change=change):
                with self.assertRaises(launcher.LauncherError):
                    launcher.live_runner_plan(**{**params, **change})

    def test_arbitrary_relative_executable_rejected(self) -> None:
        with self.assertRaises(launcher.LauncherError):
            launcher.unit_argv("foo", ["python3", "-c", "pass"], probe=True)
        with self.assertRaises(launcher.LauncherError):
            launcher.unit_argv("foo", [], probe=False)

    def test_default_cli_only_prints_no_provider_plan(self) -> None:
        output = io.StringIO()
        with (
            patch.object(subprocess, "run") as process,
            contextlib.redirect_stdout(output),
        ):
            result = launcher.main(["--run-id", "safe", "--probe-plan"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["mode"], "probe")
        process.assert_not_called()

    def test_provider_flag_rejected_for_probe(self) -> None:
        out = io.StringIO()
        with (
            patch.object(subprocess, "run") as process,
            contextlib.redirect_stderr(out),
        ):
            result = launcher.main(
                ["--run-id", "safe", "--probe-plan", "--allow-live-provider"]
            )
        self.assertEqual(result, 2)
        self.assertIn("forbidden", out.getvalue())
        process.assert_not_called()

    def test_execute_probe_mode_cannot_execute_owner_writable_python(self) -> None:
        # The privileged broker accepts an inspected systemd-run argv only.
        # Never execute mutable Python files from a developer checkout as root.
        self.assertFalse(hasattr(launcher, "subprocess"))
        with (
            patch.object(subprocess, "run") as process,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as exc:
                launcher.main(["--run-id", "safe", "--execute-probe"])
        self.assertEqual(exc.exception.code, 2)
        process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
