"""Credential mount denial: real provider-free bwrap, no ChatGPT or model traffic."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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
                "/usr/bin/bwrap", "--ro-bind", "/", "/",
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


if __name__ == "__main__":
    unittest.main()
