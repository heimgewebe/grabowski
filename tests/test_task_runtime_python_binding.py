from __future__ import annotations

import inspect
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types


import grabowski_tasks as tasks  # noqa: E402


class RuntimePythonBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime_python = Path(self.temporary.name) / "python"
        self.runtime_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.runtime_python.chmod(0o700)

    def _bind(
        self,
        command: list[str],
        *,
        transport: str = "local",
        checkout: bool = True,
        enabled: bool = True,
    ) -> list[str]:
        with (
            patch.object(tasks, "GRABOWSKI_RUNTIME_PYTHON", self.runtime_python),
            patch.object(
                tasks, "_is_local_grabowski_checkout", return_value=checkout
            ),
        ):
            return tasks._bind_grabowski_runtime_python(
                command,
                target={"transport": transport},
                cwd="/tmp/grabowski-worktree",
                enabled=enabled,
            )

    def test_task_start_runtime_python_is_explicit_opt_in(self) -> None:
        parameter = inspect.signature(tasks.grabowski_task_start).parameters[
            "runtime_python"
        ]
        self.assertIs(parameter.default, False)

    def test_default_unqualified_python_is_unchanged_without_checkout_probe(self) -> None:
        command = ["python3", "-c", "import mcp"]
        with patch.object(tasks, "_is_local_grabowski_checkout") as checkout_probe:
            result = tasks._bind_grabowski_runtime_python(
                command,
                target={"transport": "local"},
                cwd="/tmp/grabowski-worktree",
                enabled=False,
            )
        self.assertIs(result, command)
        checkout_probe.assert_not_called()

    def test_pytest_command_is_unchanged_without_opt_in(self) -> None:
        command = ["python", "-m", "pytest"]
        self.assertIs(self._bind(command, enabled=False), command)

    def test_direct_unqualified_python_uses_runtime_interpreter(self) -> None:
        command = ["python3", "-c", "import mcp"]
        self.assertEqual(
            self._bind(command),
            [str(self.runtime_python), "-c", "import mcp"],
        )
        self.assertEqual(command, ["python3", "-c", "import mcp"])

    def test_simple_env_wrapper_preserves_assignments_and_binds_python(self) -> None:
        command = ["/usr/bin/env", "PYTHONPATH=src", "python", "-c", "import mcp"]
        self.assertEqual(
            self._bind(command),
            [
                "/usr/bin/env",
                "PYTHONPATH=src",
                str(self.runtime_python),
                "-c",
                "import mcp",
            ],
        )

    def test_explicit_python_path_is_never_rewritten(self) -> None:
        command = ["/usr/bin/python3", "-c", "import sys"]
        self.assertIs(self._bind(command), command)

    def test_env_options_are_not_reinterpreted(self) -> None:
        command = ["/usr/bin/env", "-i", "python", "-c", "import sys"]
        self.assertIs(self._bind(command), command)

    def test_foreign_checkout_is_unchanged(self) -> None:
        command = ["python", "-c", "import sys"]
        self.assertIs(self._bind(command, checkout=False), command)

    def test_remote_task_is_unchanged_without_checkout_probe(self) -> None:
        command = ["python", "-c", "import sys"]
        with patch.object(
            tasks, "_is_local_grabowski_checkout"
        ) as checkout_probe:
            result = tasks._bind_grabowski_runtime_python(
                command,
                target={"transport": "ssh"},
                cwd="/remote/repository",
                enabled=True,
            )
        self.assertIs(result, command)
        checkout_probe.assert_not_called()

    def test_missing_runtime_python_fails_before_dispatch(self) -> None:
        missing = Path(self.temporary.name) / "missing-python"
        with (
            patch.object(tasks, "GRABOWSKI_RUNTIME_PYTHON", missing),
            patch.object(tasks, "_is_local_grabowski_checkout", return_value=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "runtime Python is unavailable"):
                tasks._bind_grabowski_runtime_python(
                    ["python", "-c", "import mcp"],
                    target={"transport": "local"},
                    cwd="/tmp/grabowski-worktree",
                    enabled=True,
                )

    def test_origin_normalization_accepts_canonical_github_forms(self) -> None:
        for remote in (
            "git@github.com:heimgewebe/grabowski.git",
            "ssh://git@github.com/heimgewebe/grabowski.git",
            "https://github.com/heimgewebe/grabowski.git",
            "http://github.com/heimgewebe/grabowski/",
        ):
            with self.subTest(remote=remote):
                self.assertEqual(
                    tasks._normalized_github_repository_slug(remote),
                    "heimgewebe/grabowski",
                )

    def test_checkout_identity_is_fail_closed_on_git_failure(self) -> None:
        with patch.object(
            tasks.operator,
            "_run",
            return_value={"returncode": 1, "stdout": ""},
        ):
            self.assertFalse(tasks._is_local_grabowski_checkout("/tmp/not-a-repo"))

    def test_checkout_identity_requires_exact_repository(self) -> None:
        with patch.object(
            tasks.operator,
            "_run",
            return_value={
                "returncode": 0,
                "stdout": "git@github.com:heimgewebe/not-grabowski.git\n",
            },
        ):
            self.assertFalse(tasks._is_local_grabowski_checkout("/tmp/other"))


if __name__ == "__main__":
    unittest.main()
