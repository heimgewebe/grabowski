"""Regression for the reserved runtime worker's pre-import Python environment.

The cache defense must not remove an actually pinned user-site dependency
from the system Python used by the fixed delayed worker. It does not assert
that the user site is a generally trusted source.
"""
from __future__ import annotations

import os
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
                    return_value={"XDG_RUNTIME_DIR": "/run/user/1000"}),
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
            # On this host /usr/bin/python3 imports the exact pinned PyYAML
            # 6.0.3 from user-site; -s would select system PyYAML 5.4.1.
            self.assertFalse(any("PYTHONNOUSERSITE" in arg for arg in before_command))
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
            )
            env.pop("PYTHONNOUSERSITE", None)
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
            suppressed = subprocess.run(
                ["/usr/bin/python3", "-s", *command[1:]],
                cwd=root, env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(0, suppressed.returncode)
            self.assertIn("No module named", suppressed.stderr)


if __name__ == "__main__":
    unittest.main()
