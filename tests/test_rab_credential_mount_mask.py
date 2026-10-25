"""Credential mount denial: real provider-free bwrap, no ChatGPT or model traffic."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import repobrief_agent_benchmark_codex_runner as runner  # noqa: E402


class RootCredentialMountTests(unittest.TestCase):
    def test_provider_namespace_has_root_credential_mount_mask(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir(mode=0o700)
            epoch = root / "epoch"
            epoch.mkdir(mode=0o700)
            dirs = {n: epoch / n for n in ("state", "transcripts", "evidence", "reports")}
            for directory in dirs.values():
                directory.mkdir(mode=0o700)
            parent = dirs["state"] / "codex-runtime"
            parent.mkdir(mode=0o700)
            home = parent / ("session-" + "a" * 24)
            home.mkdir(mode=0o700)
            command = runner._provider_pid_namespaced_codex_argv(
                ["/usr/bin/python3", "-I", "-c", "print('NO_PROVIDER')"],
                source=source, state_root=dirs["state"],
                transcript_root=dirs["transcripts"],
                evidence_root=dirs["evidence"],
                report_root=dirs["reports"], codex_home=home,
            )
        self.assertIn(("--tmpfs", "/run/credentials"), list(zip(command, command[1:])))
        self.assertLess(command.index("/run/credentials"), command.index("--"))

    def test_real_mount_mask_hides_artificial_root_credential(self) -> None:
        # Simulate the otherwise readable systemd LoadCredential path in
        # an unprivileged mount namespace, then mask it with a private tmpfs.
        # No real credentials are read or staged.
        with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
            source = Path(temp) / "synthetic-credentials"
            source.mkdir(mode=0o700)
            (source / "auth.json").write_bytes(b"FAKE-CREDENTIAL-ONLY")
            program = (
                "from pathlib import Path\n"
                "p=Path('/run/credentials/auth.json')\n"
                "print('LEAK' if p.is_file() else 'DENIED')\n"
                "assert Path('/etc/os-release').is_file()\n"
            )
            base = [
                runner._bwrap_path(), "--ro-bind", "/", "/",
                "--unshare-pid", "--unshare-ipc", "--die-with-parent",
                "--proc", "/proc", "--dev", "/dev",
                "--ro-bind", str(source), "/run/credentials",
            ]
            tail = ["--", "/usr/bin/python3", "-I", "-c", program]
            before = subprocess.run(
                [*base, *tail], capture_output=True, check=False, timeout=15,
            )
            self.assertEqual(before.returncode, 0, before.stderr[-1024:])
            self.assertEqual(before.stdout, b"LEAK\n")
            masked = subprocess.run(
                [*base, "--tmpfs", "/run/credentials", *tail],
                capture_output=True, check=False, timeout=15,
            )
            self.assertEqual(masked.returncode, 0, masked.stderr[-1024:])
            self.assertEqual(masked.stdout, b"DENIED\n")


    def test_real_seccomp_denies_unix_socket_to_model_tool(self) -> None:
        # Exercise the runner's existing kernel filter, not a mock or the
        # Codex permission TOML alone. No model or real credential is loaded.
        child = (
            "import socket\n"
            "try:\n"
            "    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "except PermissionError:\n"
            "    print('AF_UNIX_DENIED')\n"
            "else:\n"
            "    raise SystemExit(8)\n"
        )
        argv = runner._unix_socket_restricted_codex_argv(
            ["/usr/bin/python3", "-I", "-B", "-c", child],
            block_network=True,
        )
        result = subprocess.run(
            argv, capture_output=True, check=False, timeout=25,
            start_new_session=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr[-1024:])
        self.assertEqual(result.stdout, b"AF_UNIX_DENIED\n")


    def test_real_seccomp_rejects_unix_and_network_sockets(self) -> None:
        # This invokes the actual runner wrapper and Linux syscall filter.
        # No provider, live credentials, privileged socket or outbound traffic.
        program = (
            "import socket, sys\n"
            "for family in (socket.AF_UNIX, socket.AF_INET):\n"
            "    try:\n"
            "        sock = socket.socket(family, socket.SOCK_STREAM)\n"
            "    except PermissionError:\n"
            "        continue\n"
            "    sock.close()\n"
            "    sys.exit(9)\n"
            "print('SECURITY_SYSCALLS_DENIED')\n"
        )
        command = runner._unix_socket_restricted_codex_argv(
            [runner._validated_mcp_proxy_python(), "-I", "-c", program],
            block_network=True,
        )
        completed = subprocess.run(
            command, capture_output=True, check=False, timeout=25,
            start_new_session=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-1024:])
        self.assertEqual(completed.stdout, b"SECURITY_SYSCALLS_DENIED\n")


    def test_nixos_trusted_bwrap_is_first_on_provider_path(self) -> None:
        # The nested Codex sandbox must select the same reviewed immutable
        # bwrap binary as the outer PID namespace, not its bundled helper.
        with (
            patch.object(runner, "_validate_support_executable", return_value="/verified"),
            patch.object(runner, "_validated_mcp_proxy_python", return_value="/verified"),
        ):
            search_path = runner.validate_toolchain("/immutable/codex/bin/codex")
        if Path("/usr/bin/cat").is_file():
            self.assertEqual(search_path, "/immutable/codex/codex-path:/usr/bin:/bin")
        else:
            self.assertTrue(search_path.startswith(
                str(Path(runner._bwrap_path()).parent)
                + ":/immutable/codex/codex-path:"
            ))

    def test_nixos_no_provider_true_preserves_coreutils_argv0(self) -> None:
        # The Nix profile's 'true' symlink invokes a multicall binary that
        # does not behave like 'true' if given its resolved 'coreutils' name.
        command = runner._no_provider_true()
        if Path("/bin/true").is_file():
            self.assertEqual(command, "/bin/true")
            return
        self.assertEqual(command, "/run/current-system/sw/bin/true")
        completed = subprocess.run(
            [command], capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr[-1024:])


if __name__ == "__main__":
    unittest.main()
