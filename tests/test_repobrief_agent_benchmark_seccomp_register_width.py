"""Kernel regression for AF_UNIX family-width seccomp matching.

The raw syscall has a 64-bit argument register; the kernel socket family
argument is a 32-bit int. A high-register value must not evade the filter.
No privileged socket is contacted by this test.
"""

import platform
import shutil
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import repobrief_agent_benchmark_codex_runner as runner  # noqa: E402


_CHILD = """
import ctypes, errno, os, socket, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
family = ctypes.c_ulonglong((1 << 32) | socket.AF_UNIX)
for number, kind, socktype in ((41, 'socket', socket.SOCK_STREAM),\n                              (53, 'socketpair', socket.SOCK_DGRAM),\n                              (53, 'socketpair-seq', socket.SOCK_SEQPACKET)):
    ctypes.set_errno(0)
    if kind == 'socket':
        result = libc.syscall(ctypes.c_long(number), family,
                              ctypes.c_int(socktype), ctypes.c_int(0))
        if result >= 0:
            os.close(result)
    else:
        pair = (ctypes.c_int * 2)()
        result = libc.syscall(ctypes.c_long(number), family,
                              ctypes.c_int(socktype), ctypes.c_int(0),
                              ctypes.byref(pair))
        if result >= 0:
            os.close(pair[0]); os.close(pair[1])
    if result != -1 or ctypes.get_errno() != errno.EPERM:
        print(kind + ':NOT_DENIED', flush=True)
        sys.exit(13)
pair = (ctypes.c_int * 2)()\nresult = libc.syscall(ctypes.c_long(53), family,\n                      ctypes.c_int(socket.SOCK_STREAM), ctypes.c_int(0),\n                      ctypes.byref(pair))\nif result != 0:\n    sys.exit(14)\nos.close(pair[0]); os.close(pair[1])\nprint('RAW_UNIX_DENIED_ANON_STREAM_ALLOWED', flush=True)
"""


@unittest.skipUnless(
    platform.system() == "Linux" and platform.machine() == "x86_64",
    "x86_64 Linux seccomp syscall numbers only",
)
class CodexUnixSocketRegisterWidthTests(unittest.TestCase):
    def test_raw_high_bits_cannot_bypass_kernel_filter(self):
        command = runner._unix_socket_restricted_codex_argv(
            [str(Path(sys.executable).resolve()), "-I", "-c", _CHILD]
        )
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=(completed.stdout + completed.stderr).decode(errors="replace")[-1200:],
        )
        self.assertIn(b"RAW_UNIX_DENIED_ANON_STREAM_ALLOWED", completed.stdout)

    def test_kernel_filter_denies_cross_process_memory_syscalls(self):
        # A filtered Codex child must not recover the unfiltred parent's
        # privilege to connect to a host daemon through process_vm_*.
        child = """
import ctypes, errno, os, sys
class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
source = ctypes.create_string_buffer(b"non-secret-self-check")
target = ctypes.create_string_buffer(len(source))
outbuf = IOVec(ctypes.cast(target, ctypes.c_void_p), len(target))
inbuf = IOVec(ctypes.cast(source, ctypes.c_void_p), len(source))
for number, label, first, second in (
    (310, "process_vm_readv", outbuf, inbuf),
    (311, "process_vm_writev", inbuf, outbuf),
):
    ctypes.set_errno(0)
    result = libc.syscall(
        ctypes.c_long(number), ctypes.c_long(os.getpid()),
        ctypes.byref(first), ctypes.c_ulong(1),
        ctypes.byref(second), ctypes.c_ulong(1), ctypes.c_ulong(0),
    )
    if result != -1 or ctypes.get_errno() != errno.EPERM:
        print(label + ":NOT_DENIED", flush=True)
        sys.exit(13)
print("CROSS_PROCESS_VM_DENIED", flush=True)
"""
        command = runner._unix_socket_restricted_codex_argv(
            [str(Path(sys.executable).resolve()), "-I", "-c", child]
        )
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=(completed.stdout + completed.stderr).decode(errors="replace")[-1200:],
        )
        self.assertIn(b"CROSS_PROCESS_VM_DENIED", completed.stdout)

    def test_trusted_runner_parent_is_nondumpable_in_real_kernel(self):
        # Run PR_SET_DUMPABLE only in an isolated subprocess. The unittest
        # process itself must not become nondumpable as a test side effect.
        child = (
            "import ctypes,sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0,str(Path.cwd()/'tools'))\n"
            "import repobrief_agent_benchmark_codex_runner as runner\n"
            "runner._assert_trusted_runner_nondumpable()\n"
            "libc=ctypes.CDLL(None,use_errno=True)\n"
            "assert libc.prctl(3,0,0,0,0)==0\n"
            "print('KERNEL_PARENT_NON_DUMPABLE')\n"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", child],
            cwd=TOOLS.parent,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=(completed.stdout + completed.stderr).decode(errors="replace")[-1200:],
        )
        self.assertIn(b"KERNEL_PARENT_NON_DUMPABLE", completed.stdout)

    def test_real_codex_version_starts_inside_filter_when_installed(self):
        """Exercise Tokio startup on a real CLI without credentials or provider calls."""
        path = shutil.which("codex")
        if path is None:
            self.skipTest("Codex CLI not installed; isolated kernel tests still apply")
        with tempfile.TemporaryDirectory(prefix="rab-codex-smoke-") as home:
            completed = subprocess.run(
                runner._unix_socket_restricted_codex_argv(
                    [str(Path(path).resolve(strict=True)), "--version"]
                ),
                cwd=home,
                env={"HOME": home, "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=(completed.stdout + completed.stderr).decode(errors="replace")[
                    -1200:
                ],
            )
            self.assertIn(b"codex", completed.stdout.lower())
