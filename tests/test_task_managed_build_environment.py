from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
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


class ManagedCargoTaskEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        (self.root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        (self.root / "Justfile").write_text("ci:\n    cargo test\n", encoding="utf-8")
        (self.root / "Makefile").write_text("ci:\n\tcargo test\n", encoding="utf-8")
        self.resolver = Path(self.temporary.name) / "managed_build.py"
        self.resolver.write_text("# fixture\n", encoding="utf-8")
        self.cache_root = Path(self.temporary.name) / "managed-builds" / "cargo"
        self.cache_path = self.cache_root / ("a" * 64)
        self.target_dir = self.cache_path / "target"
        self.lock_root = Path(self.temporary.name) / "state" / "cache-locks" / "cargo"
        self.lock_path = self.lock_root / f"{self.cache_path.name}.lock"

    def _payload(self, *, profile: str = "operator-task", target: Path | None = None) -> dict:
        target_dir = self.target_dir if target is None else target
        cache_path = target_dir.parent
        return {
            "schema_version": 1,
            "kind": "heim_pc.managed_build_environment_prepared",
            "repository_root": str(self.root),
            "tool": "cargo",
            "profile": profile,
            "cache_path": str(cache_path),
            "lifecycle_lock_path": str(self.lock_root / f"{cache_path.name}.lock"),
            "environment": {"CARGO_TARGET_DIR": str(target_dir)},
            "prepared_paths": [
                str(cache_path),
                str(target_dir),
                str(self.lock_root),
            ],
        }

    def _bind(
        self,
        command: list[str],
        *,
        transport: str = "local",
        backend: str = "systemd-user",
        cargo_lock: bool = True,
        payload: dict | None = None,
    ) -> tuple[list[str], list[list[str]]]:
        lock = self.root / "Cargo.lock"
        if cargo_lock:
            if not lock.exists():
                lock.write_text("version = 3\n", encoding="utf-8")
        else:
            lock.unlink(missing_ok=True)
        invocations: list[list[str]] = []

        def fake_run(argv, **kwargs):
            invocations.append(list(argv))
            profile = argv[argv.index("--profile") + 1]
            resolved = self._payload(profile=profile) if payload is None else payload
            return {"returncode": 0, "stdout": json.dumps(resolved), "stderr": ""}

        with (
            patch.object(tasks, "MANAGED_BUILD_RESOLVER", self.resolver),
            patch.object(tasks, "MANAGED_CARGO_CACHE_ROOT", self.cache_root),
            patch.object(tasks, "MANAGED_CARGO_LOCK_ROOT", self.lock_root),
            patch.object(tasks, "_local_git_root", return_value=self.root),
            patch.object(tasks.operator, "_run", side_effect=fake_run),
            patch.dict(os.environ, {"CARGO_TARGET_DIR": ""}, clear=False),
        ):
            result = tasks._bind_managed_cargo_environment(
                command,
                target={"transport": transport},
                cwd=str(self.root),
                execution_backend=backend,
            )
        return result, invocations

    def test_direct_cargo_task_is_bound_to_external_target(self) -> None:
        result, invocations = self._bind(["cargo", "test"])
        self.assertEqual(
            result,
            [
                "/usr/bin/flock",
                "--shared",
                str(self.lock_path),
                "/usr/bin/env",
                f"CARGO_TARGET_DIR={self.target_dir}",
                "cargo",
                "test",
            ],
        )
        self.assertEqual(invocations[0][invocations[0].index("--profile") + 1], "test")

    def test_direct_cargo_profiles_remain_identity_distinct(self) -> None:
        cases = [
            (["cargo", "check"], "check"),
            (["cargo", "build", "--release"], "release"),
            (["cargo", "doc"], "doc"),
            (["cargo", "build", "--profile", "ci-fast"], "ci-fast"),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                _result, invocations = self._bind(command)
                self.assertEqual(
                    invocations[0][invocations[0].index("--profile") + 1], expected
                )

    def test_just_make_and_shell_cargo_are_bound_at_task_level(self) -> None:
        for command in (
            ["just", "ci"],
            ["make", "ci"],
            ["bash", "-lc", "cargo test"],
        ):
            with self.subTest(command=command):
                result, invocations = self._bind(command)
                self.assertEqual(
                    result[:5],
                    [
                        "/usr/bin/flock",
                        "--shared",
                        str(self.lock_path),
                        "/usr/bin/env",
                        f"CARGO_TARGET_DIR={self.target_dir}",
                    ],
                )
                self.assertEqual(result[5:], command)
                self.assertEqual(
                    invocations[0][invocations[0].index("--profile") + 1],
                    "operator-task",
                )

    def test_cargo_free_make_and_just_are_unchanged(self) -> None:
        (self.root / "Justfile").write_text("lint:\n    echo ok\n", encoding="utf-8")
        (self.root / "Makefile").write_text("lint:\n\techo ok\n", encoding="utf-8")
        for command in (["just", "lint"], ["make", "lint"]):
            with self.subTest(command=command):
                result, invocations = self._bind(command)
                self.assertIs(result, command)
                self.assertEqual(invocations, [])

    def test_in_repo_script_with_cargo_is_bound(self) -> None:
        script = self.root / "ci.sh"
        script.write_text("#!/bin/sh\ncargo test\n", encoding="utf-8")
        result, _invocations = self._bind(["bash", "ci.sh"])
        self.assertEqual(
            result[:5],
            [
                "/usr/bin/flock",
                "--shared",
                str(self.lock_path),
                "/usr/bin/env",
                f"CARGO_TARGET_DIR={self.target_dir}",
            ],
        )

    def test_non_cargo_task_is_unchanged(self) -> None:
        command = ["python3", "-c", "print('ok')"]
        result, invocations = self._bind(command)
        self.assertIs(result, command)
        self.assertEqual(invocations, [])

    def test_repo_without_cargo_lock_is_unchanged(self) -> None:
        command = ["cargo", "test"]
        result, invocations = self._bind(command, cargo_lock=False)
        self.assertIs(result, command)
        self.assertEqual(invocations, [])

    def test_explicit_cargo_target_dir_is_respected(self) -> None:
        command = ["/usr/bin/env", "CARGO_TARGET_DIR=/tmp/caller-target", "cargo", "test"]
        result, invocations = self._bind(command)
        self.assertIs(result, command)
        self.assertEqual(invocations, [])

    def test_explicit_managed_target_is_lock_only_wrapped(self) -> None:
        command = [
            "/usr/bin/env",
            f"CARGO_TARGET_DIR={self.target_dir}",
            "cargo",
            "test",
        ]
        result, invocations = self._bind(command)
        self.assertEqual(
            result,
            [
                "/usr/bin/flock",
                "--shared",
                str(self.lock_path),
                *command,
            ],
        )
        self.assertEqual(invocations, [])

    def test_explicit_managed_target_flock_wrapper_executes_child(self) -> None:
        command = [
            "/usr/bin/env",
            f"CARGO_TARGET_DIR={self.target_dir}",
            "/usr/bin/python3",
            "-c",
            "import os; assert os.environ['CARGO_TARGET_DIR'] == "
            + repr(str(self.target_dir)),
        ]
        result, invocations = self._bind(command)
        completed = subprocess.run(result, check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(invocations, [])
        self.assertTrue(self.lock_path.is_file())

    def test_shell_embedded_managed_target_override_is_rejected(self) -> None:
        command = [
            "bash",
            "-lc",
            f"CARGO_TARGET_DIR={self.target_dir} cargo test",
        ]
        with self.assertRaisesRegex(
            RuntimeError, "ambiguous managed Cargo target override"
        ):
            self._bind(command)

    def test_shell_embedded_target_override_is_not_misclassified_as_managed(self) -> None:
        command = ["bash", "-lc", "CARGO_TARGET_DIR=/tmp/caller-target cargo test"]
        result, invocations = self._bind(command)
        self.assertIs(result, command)
        self.assertEqual(invocations, [])

    def test_remote_explicit_managed_target_is_not_locally_locked(self) -> None:
        command = [
            "/usr/bin/env",
            f"CARGO_TARGET_DIR={self.target_dir}",
            "cargo",
            "test",
        ]
        result, invocations = self._bind(command, transport="ssh")
        self.assertIs(result, command)
        self.assertEqual(invocations, [])

    def test_remote_and_root_backend_tasks_are_unchanged(self) -> None:
        command = ["cargo", "test"]
        remote, remote_calls = self._bind(command, transport="ssh")
        root, root_calls = self._bind(command, backend="systemd-root-broker")
        self.assertIs(remote, command)
        self.assertIs(root, command)
        self.assertEqual(remote_calls, [])
        self.assertEqual(root_calls, [])

    def test_detected_cargo_task_fails_closed_when_resolver_is_missing(self) -> None:
        missing = Path(self.temporary.name) / "missing.py"
        with (
            patch.object(tasks, "MANAGED_BUILD_RESOLVER", missing),
            patch.object(tasks, "MANAGED_CARGO_CACHE_ROOT", self.cache_root),
            patch.object(tasks, "MANAGED_CARGO_LOCK_ROOT", self.lock_root),
            patch.object(tasks, "_local_git_root", return_value=self.root),
            patch.dict(os.environ, {"CARGO_TARGET_DIR": ""}, clear=False),
            self.assertRaisesRegex(RuntimeError, "resolver runtime is unavailable"),
        ):
            tasks._bind_managed_cargo_environment(
                ["cargo", "test"],
                target={"transport": "local"},
                cwd=str(self.root),
                execution_backend="systemd-user",
            )

    def test_resolver_target_outside_managed_cache_is_rejected(self) -> None:
        outside = Path(self.temporary.name) / "outside" / "target"
        payload = self._payload(profile="test", target=outside)
        with self.assertRaisesRegex(RuntimeError, "cache escapes"):
            self._bind(["cargo", "test"], payload=payload)

    def test_resolver_lifecycle_lock_mismatch_is_rejected(self) -> None:
        payload = self._payload(profile="test")
        payload["lifecycle_lock_path"] = "/tmp/wrong-managed-cargo.lock"
        with self.assertRaisesRegex(RuntimeError, "lifecycle lock binding"):
            self._bind(["cargo", "test"], payload=payload)

    def test_task_start_authorizes_before_preparing_managed_environment(self) -> None:
        database = Path(self.temporary.name) / "state" / "tasks.sqlite3"
        resource_database = Path(self.temporary.name) / "state" / "resources.sqlite3"
        events: list[str] = []

        def authorize(*args, **kwargs):
            events.append("authorize")

        def bind(command, **kwargs):
            events.append("prepare")
            return command

        with (
            patch.object(tasks, "TASK_DB", database),
            patch.object(tasks, "TASK_OUTCOMES_DIR", database.with_suffix(".outcomes")),
            patch.object(tasks.resources, "RESOURCE_DB", resource_database),
            patch.object(tasks.fleet, "fleet_host", return_value={"transport": "local"}),
            patch.object(tasks, "_validate_cwd", return_value=str(self.root)),
            patch.object(tasks, "_require_recovery_gate", return_value={"checked_at_unix": 1}),
            patch.object(tasks, "_task_resource_keys", return_value=([], None)),
            patch.object(tasks, "_execution_contract", return_value=("systemd-user", "user")),
            patch.object(tasks.operator, "_require_operator_mutation", side_effect=authorize),
            patch.object(tasks, "_bind_managed_cargo_environment", side_effect=bind),
            patch.object(tasks, "_dispatch", return_value={
                "returncode": 0, "stdout": "", "stderr": "", "timed_out": False,
                "stdout_truncated": False, "stderr_truncated": False,
            }),
            patch.object(tasks.base, "_append_audit"),
        ):
            tasks.grabowski_task_start(
                "heim-pc", ["cargo", "test"], cwd=str(self.root), runtime_seconds=60
            )

        self.assertEqual(events, ["authorize", "prepare"])

    def test_task_start_does_not_prepare_when_mutation_gate_rejects(self) -> None:
        database = Path(self.temporary.name) / "state" / "tasks-reject.sqlite3"
        resource_database = Path(self.temporary.name) / "state" / "resources-reject.sqlite3"
        with (
            patch.object(tasks, "TASK_DB", database),
            patch.object(tasks, "TASK_OUTCOMES_DIR", database.with_suffix(".outcomes")),
            patch.object(tasks.resources, "RESOURCE_DB", resource_database),
            patch.object(tasks.fleet, "fleet_host", return_value={"transport": "local"}),
            patch.object(tasks, "_validate_cwd", return_value=str(self.root)),
            patch.object(tasks, "_require_recovery_gate", return_value={"checked_at_unix": 1}),
            patch.object(tasks, "_task_resource_keys", return_value=([], None)),
            patch.object(tasks, "_execution_contract", return_value=("systemd-user", "user")),
            patch.object(
                tasks.operator, "_require_operator_mutation", side_effect=PermissionError("blocked")
            ),
            patch.object(tasks, "_bind_managed_cargo_environment") as bind,
            self.assertRaisesRegex(PermissionError, "blocked"),
        ):
            tasks.grabowski_task_start(
                "heim-pc", ["cargo", "test"], cwd=str(self.root), runtime_seconds=60
            )
        bind.assert_not_called()

    def test_unprepared_resolver_target_is_rejected(self) -> None:
        payload = self._payload(profile="test")
        payload["prepared_paths"] = [str(self.cache_path)]
        with self.assertRaisesRegex(RuntimeError, "did not prepare"):
            self._bind(["cargo", "test"], payload=payload)


if __name__ == "__main__":
    unittest.main()
