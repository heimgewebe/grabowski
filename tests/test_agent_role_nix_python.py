from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_agent_role as role
import grabowski_agent_sandbox as sandbox


class NixPythonProbeTests(unittest.TestCase):
    def test_usr_python_remains_admissible_without_nix_store(self) -> None:
        with mock.patch.object(sandbox, "_trusted_nix_store", side_effect=AssertionError("unnecessary store trust")):
            self.assertTrue(sandbox._sandbox_python_path_allowed(Path("/usr/bin/python3")))

    def test_home_virtualenv_and_external_paths_are_denied(self) -> None:
        for path in ("/home/alex/.venv/bin/python3", "/tmp/python3", "/opt/rogue/python3"):
            with self.subTest(path=path):
                self.assertFalse(sandbox._sandbox_python_path_allowed(Path(path)))

    def test_nix_python_requires_the_same_fixed_trusted_store_mount(self) -> None:
        interpreter = Path("/nix/store/0123456789abcdef0123456789abcdef-python/bin/python3")
        with mock.patch.object(sandbox, "_trusted_nix_store", return_value=Path("/nix/store")) as trust:
            self.assertTrue(sandbox._sandbox_python_path_allowed(interpreter))
            trust.assert_called_once_with()
        with mock.patch.object(sandbox, "_trusted_nix_store", return_value=None):
            self.assertFalse(sandbox._sandbox_python_path_allowed(interpreter))
        with mock.patch.object(sandbox, "_trusted_nix_store", return_value=Path("/other/store")):
            self.assertFalse(sandbox._sandbox_python_path_allowed(interpreter))

    def test_untrusted_store_does_not_fall_back_to_host_python(self) -> None:
        interpreter = Path("/nix/store/0123456789abcdef0123456789abcdef-python/bin/python3")
        with mock.patch.object(sandbox, "_trusted_nix_store", side_effect=sandbox.AgentSandboxError("not trusted")):
            with self.assertRaisesRegex(sandbox.AgentSandboxError, "not trusted"):
                sandbox._sandbox_python_path_allowed(interpreter)

    def test_codex_wrapper_uses_the_same_trusted_python(self) -> None:
        interpreter = Path("/nix/store/0123456789abcdef0123456789abcdef-python/bin/python3")
        with (
            mock.patch.object(sandbox, "sandbox_python_executable", return_value=interpreter),
            mock.patch.object(sandbox, "_resolved_executable", return_value=Path("/tmp/codex")),
            mock.patch.object(sandbox, "_codex_sandbox_auth_files",
                              return_value=(Path("/tmp/codex-auth.json"), Path("/tmp/codex-auth.lock"))),
        ):
            prepared = sandbox.prepare_external_agent_command(["codex"])
        self.assertEqual(prepared.command[:3], (str(interpreter), "-I", "-S"))

    def test_real_nixos_probe_finds_store_python_inside_read_only_sandbox(self) -> None:
        native_python = Path(sys.executable).resolve(strict=True)
        store = Path("/nix/store")
        if not native_python.is_relative_to(store):
            self.skipTest("not running on a Nix-store Python interpreter")
        resolved = role._sandbox_probe_python()
        self.assertEqual(Path(resolved), native_python)
        self.assertEqual(sandbox.sandbox_python_executable(), native_python)
        with mock.patch.object(sandbox, "_trusted_nix_store", return_value=store):
            self.assertTrue(sandbox._sandbox_python_path_allowed(Path(resolved)))

        binary = (
            os.environ.get("GRABOWSKI_BWRAP_BIN")
            or shutil.which("bwrap")
            or next((str(p) for p in store.glob("*-bubblewrap-*/bin/bwrap")), None)
        )
        self.assertIsNotNone(binary, "NixOS R3 role requires real bubblewrap")
        assert binary is not None
        command = [resolved, "-I", "-S", "-c", "import sys;print(sys.executable)"]
        argv = sandbox.minimal_sandbox_argv(
            workspace=ROOT,
            command=command,
            workspace_writable=False,
        )
        self.assertIn(["--ro-bind", "/nix/store", "/nix/store"],
                      [argv[n:n + 3] for n in range(len(argv) - 2)])
        result = subprocess.run(
            [str(Path(binary).resolve(strict=True)), *argv[1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout.decode().strip(), str(native_python))


if __name__ == "__main__":
    unittest.main()