"""Exact tests for the no-provider root-systemd launcher and future live plan."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
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
                "-/run/user",
                "-/run/docker",
                "-/mnt/backup",
                "-/dev/hugepages",
                "-/var/lib/private",
            ],
        )
        self.assertNotIn("StateDirectory", p)
        self.assertNotIn("StateDirectoryMode", p)

    def test_optional_absent_host_paths_do_not_break_unit_setup(self) -> None:
        # Missing host sockets/backups must not abort namespace setup. The
        # persistent StateDirectory alias remains an essential LIVE mask.
        for probe in (True, False):
            with self.subTest(probe=probe):
                p = self.props(
                    launcher.unit_argv("optional", ["/usr/bin/true"], probe=probe)
                )
                masked = p["InaccessiblePaths"].split()
                self.assertEqual(
                    masked[:4],
                    ["-/run/user", "-/run/docker", "-/mnt/backup", "-/dev/hugepages"],
                )
                self.assertEqual(
                    masked[4], "-/var/lib/private" if probe else "/var/lib/private"
                )

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

    def test_live_service_outlives_max_provider_wall_and_cleanup(self) -> None:
        # The runner accepts 3600s provider wall time. Systemd includes the
        # setup and postflight phases in its service lifetime, so 900s would
        # kill the runner after one-shot intent and before ledger finalization.
        probe = self.props(launcher.probe_argv("probe"))
        live = self.props(
            launcher.unit_argv("longwall", ["/usr/bin/true"], probe=False)
        )
        self.assertEqual(probe["RuntimeMaxSec"], "30")
        # Full service lifetime: provider + at most twenty 120s Git phases
        # spanning preflight/checkout/postflight, four 90s isolated readbacks,
        # source tree, login, sandbox, and 300s ledger/cleanup allowance.
        # All bounded startup checks are inside the same service deadline,
        # including 15s provider PIDNS and 25s nested Codex-in-PIDNS smoke.
        min_service_seconds = (
            3600 + (20 * 120) + (4 * 90) + 30 + 10 + 25 + 15 + 25 + 300
        )
        self.assertGreaterEqual(int(live["RuntimeMaxSec"]), min_service_seconds)
        self.assertEqual(int(live["RuntimeMaxSec"]), 7200)
        self.assertEqual(int(live["RuntimeMaxSec"]) - min_service_seconds, 435)
        pair = self.props(
            launcher.unit_argv("pairbudget", ["/usr/bin/true"], probe=False, pair=True)
        )
        self.assertEqual(int(pair["RuntimeMaxSec"]), 21600)
        self.assertEqual(
            int(pair["RuntimeMaxSec"]), 2 * int(live["RuntimeMaxSec"]) + 7200
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

    @patch.object(
        launcher, "_frozen_bootstrap_program", return_value="frozen-test-only"
    )
    def test_live_plan_uses_proven_physical_state_root_binding(
        self, _program: object
    ) -> None:
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

    def test_live_plan_uses_captured_immutable_bootstrap(self) -> None:
        target = Path("/usr/local/libexec/repobrief_agent_benchmark_codex_runner.py")
        code = "print('FROZEN_BOOTSTRAP')"
        with patch.object(
            launcher, "_frozen_bootstrap_program", return_value=code, create=True
        ) as frozen:
            cmd = launcher.live_runner_plan(
                "boot",
                target,
                Path("/requests"),
                Path("/map.json"),
                Path("/usr/bin/codex"),
                "a" * 64,
            )
        frozen.assert_called_once_with(target)
        child = cmd[cmd.index("--") + 1 :]
        self.assertEqual(child[:5], ["/usr/bin/python3", "-I", "-B", "-c", code])
        self.assertEqual(child[5], str(target))
        self.assertIn("--request-root", child)
        self.assertNotIn("--allow-live-provider", child)

    @patch.object(
        launcher, "_frozen_bootstrap_program", return_value="frozen-test-only"
    )
    def test_live_plan_provider_optin_does_not_start_any_process(
        self, _program: object
    ) -> None:
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

    def test_live_plan_requires_root_owned_staged_bootstrap(self) -> None:
        # The plan helper must not embed arbitrary user-writable Python bytes.
        with self.assertRaises(launcher.LauncherError):
            launcher._frozen_bootstrap_program(
                Path("/tmp/nonexistent/repobrief_agent_benchmark_codex_runner.py")
            )

    def test_live_plan_checks_all_root_owned_imported_sources(self) -> None:
        target = Path("/usr/local/libexec/repobrief_agent_benchmark_codex_runner.py")
        required = {
            "repobrief_agent_benchmark_preflight_core.py",
            "repobrief_agent_benchmark_codex_preflight.py",
            "repobrief_agent_benchmark_runner.py",
            "repobrief_agent_benchmark_source_bootstrap.py",
            "repobrief_agent_benchmark_codex_runner.py",
        }
        inspected: list[str] = []

        def trusted(path: Path, *, maximum: int) -> bytes:
            inspected.append(path.name)
            self.assertEqual(path.parent, target.parent)
            self.assertGreater(maximum, 0)
            return b"print('captured')\n"

        with patch.object(launcher, "_root_owned_source", side_effect=trusted):
            command = launcher.live_runner_plan(
                "closed",
                target,
                Path("/requests"),
                Path("/map.json"),
                Path("/usr/local/bin/codex"),
                "a" * 64,
            )
        self.assertEqual(set(inspected), required)
        self.assertEqual(len(inspected), len(required))
        self.assertIn("print('captured')\n", command)

        def compromised(path: Path, *, maximum: int) -> bytes:
            if path.name == "repobrief_agent_benchmark_preflight_core.py":
                raise launcher.LauncherError("live source is not root-owned immutable")
            return b"print('captured')\n"

        with (
            patch.object(launcher, "_root_owned_source", side_effect=compromised),
            self.assertRaisesRegex(launcher.LauncherError, "root-owned immutable"),
        ):
            launcher.live_runner_plan(
                "closed",
                target,
                Path("/requests"),
                Path("/map.json"),
                Path("/usr/local/bin/codex"),
                "a" * 64,
                allow_live_provider=True,
            )

    def test_pair_plan_checks_all_transitive_source_files(self) -> None:
        target = Path("/usr/local/libexec/repobrief_agent_benchmark_codex_runner.py")
        inspected: list[str] = []

        def trusted(path: Path, *, maximum: int) -> bytes:
            inspected.append(path.name)
            if path.name == "repobrief_agent_benchmark_runner.py":
                raise launcher.LauncherError("live source is not root-owned immutable")
            return b"print('captured')\n"

        with (
            patch.object(launcher, "_root_owned_source", side_effect=trusted),
            self.assertRaisesRegex(launcher.LauncherError, "root-owned immutable"),
        ):
            launcher.live_pair_plan(
                "bound",
                target,
                target.with_name("repobrief_agent_benchmark_codex_preflight.py"),
                Path("/requests"),
                Path("/map.json"),
                Path("/usr/local/bin/codex"),
                "a" * 64,
                "bound:case:r1",
                Path("/validator.json"),
                "1.00",
                allow_live_provider=True,
            )
        self.assertIn("repobrief_agent_benchmark_runner.py", inspected)

    def test_real_root_owned_source_and_untrusted_writable_sibling(self) -> None:
        # Exercise the real descriptor/ownership code, not a mocked predicate.
        # /usr/bin/env is a pre-installed root-owned file on Linux test hosts.
        system_file = Path("/usr/bin/env")
        if not system_file.is_file() or system_file.is_symlink():
            self.skipTest("host lacks a regular /usr/bin/env")
        raw = launcher._root_owned_source(system_file, maximum=16 * 1024 * 1024)
        self.assertGreater(len(raw), 0)

        # This writable sibling must be denied without executing its content.
        with tempfile.TemporaryDirectory(prefix="rab-source-closure-") as root:
            sibling = Path(root) / "repobrief_agent_benchmark_runner.py"
            sibling.write_text(
                "raise RuntimeError('untrusted import ran')\\n", encoding="utf-8"
            )
            sibling.chmod(0o666)
            with self.assertRaisesRegex(launcher.LauncherError, "root-owned immutable"):
                launcher._root_owned_source(sibling, maximum=1024 * 1024)

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


class RootSystemdPairPlanTests(unittest.TestCase):
    @staticmethod
    def arguments() -> dict:
        return {
            "run_id": "bound",
            "runner": Path(
                "/usr/local/libexec/repobrief_agent_benchmark_codex_runner.py"
            ),
            "preflight": Path(
                "/usr/local/libexec/repobrief_agent_benchmark_codex_preflight.py"
            ),
            "request_root": Path("/frozen/requests"),
            "repository_map": Path("/frozen/repository-map.json"),
            "codex": Path("/usr/local/bin/codex"),
            "codex_sha256": "a" * 64,
            "pair_id": "frozen-pair",
            "validator_command": Path("/frozen/validator.json"),
            "max_cost_usd": "1.00",
            "allow_live_provider": True,
        }

    def test_pair_uses_one_root_service_with_bootstrapped_preflight_main(
        self,
    ) -> None:
        with patch.object(
            launcher, "_frozen_bootstrap_program", return_value="captured-bootstrap"
        ) as frozen:
            command = launcher.live_pair_plan(**self.arguments())
        self.assertEqual(
            frozen.call_args_list[0].args[0],
            self.arguments()["runner"],
        )
        self.assertEqual(
            frozen.call_args_list[1].args[0],
            self.arguments()["preflight"],
        )
        self.assertEqual(frozen.call_count, 2)
        self.assertEqual(command[:3], ["/usr/bin/systemd-run", "--system", "--wait"])
        self.assertEqual(command.count("--"), 1)
        self.assertIn("--unit=grabowski-rab-bound", command)
        self.assertNotIn("--collect", command)
        props = RootSystemdLauncherTests.props(command)
        self.assertEqual(props["Type"], "exec")
        self.assertEqual(props["DynamicUser"], "yes")
        self.assertEqual(props["DevicePolicy"], "closed")
        self.assertEqual(props["RuntimeMaxSec"], "21600")
        self.assertEqual(
            props["ReadWritePaths"].split(),
            [
                f"/var/lib/grabowski-rab-bound/epoch/{leaf}"
                for leaf in launcher._OUTPUTS
            ],
        )
        child = command[command.index("--") + 1 :]
        self.assertEqual(
            child[:5], ["/usr/bin/python3", "-I", "-B", "-c", "captured-bootstrap"]
        )
        self.assertEqual(child[5], str(self.arguments()["preflight"]))
        self.assertIn("--execute-pair", child)
        self.assertIn("--allow-live-provider", child)
        self.assertIn("--pair-id", child)
        self.assertEqual(child[child.index("--pair-id") + 1], "frozen-pair")
        self.assertEqual(
            child[child.index("--state-root") + 1],
            "/var/lib/grabowski-rab-bound/epoch/state",
        )
        self.assertEqual(
            child[child.index("--report-out") + 1],
            "/var/lib/grabowski-rab-bound/epoch/reports/preflight.json",
        )
        # No second ExecStart, shell, or unfiltered same-UID supervisor.
        self.assertNotIn("sh", child)
        self.assertNotIn("bash", child)

    def test_pair_plan_rejects_opt_in_path_identity_and_cost_errors(
        self,
    ) -> None:
        arguments = self.arguments()
        cases = (
            {"allow_live_provider": False},
            {"runner": Path("/tmp/other.py")},
            {"preflight": Path("/usr/local/libexec/unqualified.py")},
            {"preflight": Path("/tmp/repobrief_agent_benchmark_codex_preflight.py")},
            {"pair_id": ""},
            {"pair_id": "line\nbreak"},
            {"codex_sha256": "a" * 63},
            {"max_cost_usd": "0"},
            {"max_cost_usd": "1.01"},
            {"max_cost_usd": "NaN"},
            {"validator_command": Path("../validator.json")},
        )
        for changed in cases:
            with (
                self.subTest(changed=changed),
                patch.object(launcher, "_frozen_bootstrap_program") as capture,
            ):
                with self.assertRaises(launcher.LauncherError):
                    launcher.live_pair_plan(**{**arguments, **changed})
                capture.assert_not_called()
        with self.assertRaisesRegex(launcher.LauncherError, "cannot be a no-provider"):
            launcher.unit_argv("bound", ["/usr/bin/true"], probe=True, pair=True)

    def test_pair_cli_prints_inert_plan_without_invoking_python_or_provider(
        self,
    ) -> None:
        with (
            patch.object(
                launcher, "_frozen_bootstrap_program", return_value="frozen-test"
            ),
            patch.object(subprocess, "run") as invocation,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            result = launcher.main(
                [
                    "--run-id",
                    "bound",
                    "--live-pair-plan",
                    "--runner",
                    str(self.arguments()["runner"]),
                    "--preflight",
                    str(self.arguments()["preflight"]),
                    "--request-root",
                    "/frozen/requests",
                    "--repository-map",
                    "/frozen/repository-map.json",
                    "--codex",
                    "/usr/local/bin/codex",
                    "--codex-sha256",
                    "a" * 64,
                    "--pair-id",
                    "frozen-pair",
                    "--validator-command",
                    "/frozen/validator.json",
                    "--max-cost-usd",
                    "1.00",
                    "--allow-live-provider",
                ]
            )
        self.assertEqual(result, 0)
        command = json.loads(output.getvalue())
        self.assertEqual(command["mode"], "pair-live-plan-only")
        self.assertIn("--execute-pair", command["argv"])
        invocation.assert_not_called()


if __name__ == "__main__":
    unittest.main()
