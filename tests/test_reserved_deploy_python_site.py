"""Regression for the reserved runtime worker's pre-import Python environment.

The cache defense must not remove an actually pinned user-site dependency
from the system Python used by the fixed delayed worker. It does not assert
that the user site is a generally trusted source.
"""
from __future__ import annotations

import os
import pwd
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

from test_operator_contract import _load_operator_module


class ReservedWorkerPythonSiteTests(unittest.TestCase):
    def test_reserved_worker_uses_private_pycache_without_dropping_user_site(self):
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory(prefix="reserved-worker-pyyaml-test-") as tmp:
            root = Path(tmp)
            working = root / "work"
            working.mkdir()
            launch_result = {
                "returncode": 0, "stdout": "started", "stderr": "",
                "argv": [], "argv_sha256": "0" * 64, "command": "systemd-run",
                "cwd": str(root), "timed_out": False,
                "duration_seconds": 0.01, "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with (
                patch.object(operator, "STATE_DIR", root / "state"),
                patch.object(operator, "JOBS_DIR", root / "state" / "jobs"),
                patch.object(operator.uuid, "uuid4",
                    return_value=types.SimpleNamespace(hex="aaaa1111222233334444")),
                patch.object(operator, "_managed_runtime_environment",
                    return_value={
                        "XDG_RUNTIME_DIR": "/run/user/1000",
                        "PYTHONNOUSERSITE": "1",
                        "PYTHONUSERBASE": "/tmp/untrusted-python-site",
                        "PYTHONWARNINGS": "error",
                        "PYTHONSAFEPATH": "1",
                        "PYTHONPLATLIBDIR": "foreign",
                        "PYTHONINSPECT": "1",
                        "PYTHONSTARTUP": "/tmp/untrusted-startup",
                        "PYTHONHASHSEED": "bogus",
                        "PYTHONMALLOC": "bogus",
                        "PYTHONUTF8": "bogus",
                        "PYTHONIOENCODING": "not-a-codec",
                        "PYTHONINTMAXSTRDIGITS": "bogus",
                        "PYTHONOPTIMIZE": "bogus",
                    }),
                patch.object(operator, "_run", return_value=launch_result) as run,
            ):
                job = operator._start_job(
                    ["/usr/bin/python3", "-c", "print('worker')"],
                    cwd=str(working), runtime_seconds=60,
                    finalization_expected_head="a" * 40,
                    allow_reserved_runtime_deploy=True,
                )
            self.assertEqual("launch_submitted", job["final_status"])
            argv = run.call_args_list[0].args[0]
            before_command = argv[:argv.index("--")]
            self.assertIn(
                "--setenv=PYTHONPYCACHEPREFIX=/dev/null/grabowski-runtime-deploy",
                before_command,
            )
            self.assertIn("--setenv=PYTHONPATH=", before_command)
            self.assertIn("--setenv=PYTHONHOME=", before_command)
            # Explicitly override hostile user-manager Python environment,
            # but do not claim that the mutable user site is authenticated.
            for item in (
                "--setenv=PYTHONNOUSERSITE=",
                "--setenv=PYTHONWARNINGS=",
                "--setenv=PYTHONSAFEPATH=",
                "--setenv=PYTHONPLATLIBDIR=",
                "--setenv=PYTHONINSPECT=",
                "--setenv=PYTHONSTARTUP=",
                "--setenv=PYTHONBREAKPOINT=0",
            ):
                self.assertIn(item, before_command)
            # A manager-level invalid Python setting must be overridden
            # before the fixed /usr/bin/python3 processes any user code.
            neutral = {
                "PYTHONHASHSEED": "random",
                "PYTHONMALLOC": "",
                "PYTHONUTF8": "",
                "PYTHONIOENCODING": "",
                "PYTHONINTMAXSTRDIGITS": "",
                "PYTHONCOERCECLOCALE": "",
                "PYTHONDEBUG": "",
                "PYTHONOPTIMIZE": "",
                "PYTHONUNBUFFERED": "",
                "PYTHONVERBOSE": "",
                "PYTHONFAULTHANDLER": "",
                "PYTHONDEVMODE": "",
                "PYTHONWARNDEFAULTENCODING": "",
                "PYTHONTRACEMALLOC": "",
                "PYTHONPROFILEIMPORTTIME": "",
                "PYTHONASYNCIODEBUG": "",
                "PYTHONDONTWRITEBYTECODE": "",
            }
            for name, value in neutral.items():
                self.assertEqual(1, before_command.count(f"--setenv={name}={value}"), name)
            # Probe actual interpreter preinitialization with -S solely to
            # prevent tests from loading any user-site .pth or bytecode.
            if Path("/usr/bin/python3").is_file():
                for name in ("PYTHONHASHSEED", "PYTHONMALLOC"):
                    with self.subTest(inherited=name):
                        poisoned = {"PATH": os.environ.get("PATH", "/usr/bin"),
                                    "HOME": str(root), name: "bogus"}
                        command = ["/usr/bin/python3", "-S", "-c", "print('preinit-ok')"]
                        unsafe = subprocess.run(
                            command, cwd=root, env=poisoned,
                            capture_output=True, text=True, timeout=10,
                        )
                        self.assertNotEqual(0, unsafe.returncode)
                        admitted = dict(poisoned)
                        for option in before_command:
                            if option.startswith("--setenv="):
                                key, _, value = option[len("--setenv="):].partition("=")
                                admitted[key] = value
                        safe = subprocess.run(
                            command, cwd=root, env=admitted,
                            capture_output=True, text=True, timeout=10,
                        )
                        self.assertEqual(0, safe.returncode, safe.stderr)
                        self.assertEqual("preinit-ok", safe.stdout.strip())

            expected_site = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local"
            self.assertIn(f"--setenv=PYTHONUSERBASE={expected_site}", before_command)
            self.assertEqual(
                1, sum(arg.startswith("--setenv=PYTHONUSERBASE=") for arg in before_command)
            )
            self.assertNotIn("--setenv=PYTHONUSERBASE=/tmp/untrusted-python-site", before_command)
            self.assertEqual(
                argv[argv.index("--") + 1:],
                operator.command_identity.systemd_escape_argv(
                    ["/usr/bin/python3", "-c", "print('worker')"]
                ),
            )

    def test_private_cache_prefix_does_not_prevent_pinned_user_site_import(self):
        # Environment-controlled user-site fixture, independent of host versions.
        with tempfile.TemporaryDirectory(prefix="reserved-worker-site-fixture-") as tmp:
            root = Path(tmp)
            base = root / "user"
            env = os.environ.copy()
            env.update(
                PYTHONUSERBASE=str(base), PYTHONPATH="", PYTHONHOME="",
                PYTHONPYCACHEPREFIX="/dev/null/grabowski-runtime-deploy",
                PYTHONNOUSERSITE="",
            )
            env.pop("PYTHONSAFEPATH", None)
            site_path = subprocess.run(
                ["/usr/bin/python3", "-c", "import site; print(site.getusersitepackages())"],
                cwd=root, env=env, capture_output=True, text=True, timeout=10, check=True,
            ).stdout.strip()
            site = Path(site_path)
            site.mkdir(parents=True, exist_ok=True)
            (site / "grabowski_fake_pinned_deploy_dep.py").write_text(
                'VERSION = "6.0.3"\n', encoding="utf-8"
            )
            command = [
                "/usr/bin/python3", "-c",
                "import grabowski_fake_pinned_deploy_dep as dep; print(dep.VERSION)",
            ]
            allowed = subprocess.run(
                command, cwd=root, env=env, capture_output=True, text=True, timeout=10
            )
            self.assertEqual(0, allowed.returncode, allowed.stderr)
            self.assertEqual("6.0.3", allowed.stdout.strip())
            suppressed_by_env = subprocess.run(
                command, cwd=root, env={**env, "PYTHONNOUSERSITE": "1"},
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(0, suppressed_by_env.returncode)
            self.assertIn("No module named", suppressed_by_env.stderr)
            suppressed = subprocess.run(
                ["/usr/bin/python3", "-s", *command[1:]],
                cwd=root, env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(0, suppressed.returncode)
            self.assertIn("No module named", suppressed.stderr)


    @unittest.skipUnless(Path("/usr/bin/python3").is_file(), "system Python absent")
    def test_private_cache_prefix_ignores_stale_same_mtime_user_site_bytecode(self):
        # Positive control for the narrow pycache guarantee, not source trust:
        # a mutable .pth or sourceless .pyc remains outside this protection.
        with tempfile.TemporaryDirectory(prefix="reserved-worker-cache-negative-") as tmp:
            root = Path(tmp)
            env = os.environ.copy()
            env.update(
                PYTHONUSERBASE=str(root / "user"),
                PYTHONPATH="", PYTHONHOME="", PYTHONNOUSERSITE="",
            )
            for key in ("PYTHONPYCACHEPREFIX", "PYTHONDONTWRITEBYTECODE", "PYTHONSAFEPATH"):
                env.pop(key, None)
            site = Path(subprocess.run(
                ["/usr/bin/python3", "-c", "import site; print(site.getusersitepackages())"],
                cwd=root, env=env, capture_output=True, text=True,
                timeout=10, check=True,
            ).stdout.strip())
            site.mkdir(parents=True, exist_ok=True)
            module = site / "grabowski_reserved_cache_control.py"
            module.write_text("VALUE = 'POISONED'\n", encoding="ascii")
            command = [
                "/usr/bin/python3", "-c",
                "import grabowski_reserved_cache_control as dep; print(dep.VALUE)",
            ]
            first = subprocess.run(
                command, cwd=root, env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(0, first.returncode, first.stderr)
            self.assertEqual("POISONED", first.stdout.strip())
            self.assertTrue((site / "__pycache__").is_dir())
            original = module.stat()
            # Same mtime and byte count leave a plausible stale timestamp .pyc.
            module.write_text("VALUE = 'ORIGINAL'\n", encoding="ascii")
            os.utime(module, ns=(original.st_atime_ns, original.st_mtime_ns))
            unsafe = subprocess.run(
                command, cwd=root, env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(0, unsafe.returncode, unsafe.stderr)
            self.assertEqual("POISONED", unsafe.stdout.strip())
            isolated = subprocess.run(
                command, cwd=root,
                env={**env, "PYTHONPYCACHEPREFIX": "/dev/null/grabowski-runtime-deploy"},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(0, isolated.returncode, isolated.stderr)
            self.assertEqual("ORIGINAL", isolated.stdout.strip())


if __name__ == "__main__":
    unittest.main()