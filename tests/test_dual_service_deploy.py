from __future__ import annotations

import ast
import contextlib
import ctypes
import errno
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import deploy_runtime as core
import deploy_runtime_dual as dual


RUNTIME = Path("/home/alex/.local/share/grabowski-mcp")
CONTRACT = core.load_contract(ROOT / "config" / "runtime-entrypoint.json")
TEST_AGENT_INSTRUCTIONS = (
    "Grabowski agent-facing contract grabowski-agent-facing-contract-v1 "
    "(schema 1).\n"
    "1. [truth-hierarchy] Runtime truth first."
)
TEST_AGENT_INSTRUCTIONS_IDENTITY = core.agent_instructions_identity(
    TEST_AGENT_INSTRUCTIONS
)


def observation(active: bool) -> core.ServiceObservation:
    return core.ServiceObservation(
        query_valid=True,
        load_state="loaded",
        active_state="active" if active else "inactive",
        sub_state="running" if active else "dead",
        main_pid=123 if active else 0,
        returncode=0,
    )


class ProfileTopologyTests(unittest.TestCase):
    def topology(self, payload):
        with mock.patch.object(dual, "_load_yaml", return_value=payload):
            return dual.profile_topology(Path("profile.yaml"), RUNTIME)

    def test_url_profile_without_command_is_accepted(self) -> None:
        result = self.topology(
            {"mcp": {"server_urls": [{"url": "http://127.0.0.1:18181/mcp"}]}}
        )
        self.assertEqual(result.kind, "url")
        self.assertEqual(result.server_url_count, 1)

    def test_legacy_command_profile_is_preserved(self) -> None:
        result = self.topology(
            {
                "command": [
                    str(RUNTIME / ".venv/bin/python"),
                    "-m",
                    CONTRACT.module,
                ]
            }
        )
        self.assertEqual(result.kind, "legacy-stdio")
        self.assertIsNotNone(result.legacy_entrypoint)

    def test_mixed_command_and_url_profile_is_rejected(self) -> None:
        payload = {
            "command": [
                str(RUNTIME / ".venv/bin/python"),
                "-m",
                CONTRACT.module,
            ],
            "mcp": {"server_urls": [{"url": "http://127.0.0.1:18181/mcp"}]},
        }
        with self.assertRaises(core.DeployError):
            self.topology(payload)

    def test_empty_or_wrongly_typed_server_urls_are_rejected(self) -> None:
        invalid = [
            {"mcp": {"server_urls": []}},
            {"mcp": {"server_urls": "http://127.0.0.1:18181/mcp"}},
            {"mcp": {"server_urls": [42]}},
            {"mcp": {"server_urls": [{}]}},
            {"mcp": {"server_urls": [{"url": ""}]}},
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(core.DeployError):
                    self.topology(payload)

    def test_multiple_commands_are_rejected(self) -> None:
        payload = {
            "outer": {
                "command": [
                    str(RUNTIME / ".venv/bin/python"),
                    "-m",
                    CONTRACT.module,
                ]
            },
            "other": {
                "command": [
                    str(RUNTIME / ".venv/bin/python"),
                    "-m",
                    CONTRACT.module,
                ]
            },
        }
        with self.assertRaises(core.DeployError):
            self.topology(payload)


class OperatorIdentityTests(unittest.TestCase):
    def test_expected_operator_argv_is_exact(self) -> None:
        self.assertEqual(
            dual.expected_operator_argv(RUNTIME, CONTRACT),
            [
                str(RUNTIME / ".venv/bin/python"),
                "-m",
                CONTRACT.module,
                "--transport",
                "streamable-http",
                "--host",
                "127.0.0.1",
                "--port",
                "18181",
            ],
        )

    def test_operator_process_accepts_only_exact_argv_and_python(self) -> None:
        expected = dual.expected_operator_argv(RUNTIME, CONTRACT)
        python_path = RUNTIME / ".venv/bin/python"
        with (
            mock.patch.object(dual, "_service_main_pid", return_value=456),
            mock.patch.object(core, "process_argv", return_value=expected),
            mock.patch.object(core, "process_exe", return_value=python_path),
            mock.patch.object(
                core,
                "verify_entrypoint_importable",
                return_value=Path("/release/grabowski_operator.py"),
            ),
            mock.patch.object(Path, "resolve", autospec=True, side_effect=lambda value: value),
        ):
            result = dual.verify_operator_process(RUNTIME, CONTRACT)
        self.assertEqual(result["pid"], 456)

    def test_wrong_host_port_or_module_is_rejected(self) -> None:
        expected = dual.expected_operator_argv(RUNTIME, CONTRACT)
        variants = [
            [*expected[:-3], "0.0.0.0", *expected[-2:]],
            [*expected[:-1], "9999"],
            [expected[0], "-m", "other_module", *expected[3:]],
        ]
        for argv in variants:
            with self.subTest(argv=argv):
                with (
                    mock.patch.object(dual, "_service_main_pid", return_value=456),
                    mock.patch.object(core, "process_argv", return_value=argv),
                ):
                    with self.assertRaises(core.DeployError):
                        dual.verify_operator_process(RUNTIME, CONTRACT)


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class OperatorListenerGateTests(unittest.TestCase):
    def test_listener_gate_waits_for_two_consecutive_successful_samples(self) -> None:
        with (
            mock.patch.object(
                dual.socket,
                "create_connection",
                side_effect=[
                    ConnectionRefusedError("refused"),
                    FakeSocket(),
                    ConnectionRefusedError("flapped"),
                    FakeSocket(),
                    FakeSocket(),
                ],
            ) as connect,
            mock.patch.object(dual.time, "sleep"),
        ):
            result = dual.require_operator_listener(timeout_seconds=1)
        self.assertEqual(result["successful_samples"], 2)
        self.assertEqual(result["attempts"], 5)
        self.assertEqual(connect.call_count, 5)

    def test_listener_gate_fails_closed_on_timeout(self) -> None:
        with (
            mock.patch.object(
                dual.socket,
                "create_connection",
                side_effect=ConnectionRefusedError("refused"),
            ),
            mock.patch.object(
                dual.time,
                "monotonic",
                side_effect=[0.0, 0.0, 0.0, 0.1, 0.1, 0.31],
            ),
            mock.patch.object(dual.time, "sleep"),
        ):
            with self.assertRaisesRegex(core.DeployError, "Operator-Listener"):
                dual.require_operator_listener(timeout_seconds=0.3)


class SafetyObserverUnitTests(unittest.TestCase):
    EXPECTED_RELATIONS = {
        "Wants",
        "Requires",
        "Requisite",
        "BindsTo",
        "PartOf",
        "Upholds",
        "Conflicts",
        "OnFailure",
        "OnSuccess",
        "PropagatesReloadTo",
        "ReloadPropagatedFrom",
        "PropagatesStopTo",
        "StopPropagatedFrom",
        "JoinsNamespaceOf",
    }

    def setUp(self) -> None:
        self.expected = (ROOT / dual.SAFETY_OBSERVER_UNIT_RELATIVE).read_bytes()
        self.snapshot = SimpleNamespace(repo_head="a" * 40)

    def retained_paths(self, target: Path) -> list[Path]:
        return sorted(
            target.parent.glob(f".{target.name}.retained-*")
        )

    def incoming_paths(self, target: Path) -> list[Path]:
        return sorted(
            target.parent.glob(f".{target.name}.incoming-*")
        )

    def show_output(
        self,
        target: Path,
        *,
        relations: dict[str, str] | None = None,
        effective: dict[str, str] | None = None,
        after: str | None = None,
        exec_start: str | None = None,
        drop_ins: str = "",
        effective_sets: dict[str, str] | None = None,
    ) -> str:
        relation_values = relations or {}
        output = "".join(
            f"{name}={relation_values.get(name, '')}\n"
            for name in sorted(dual.OBSERVER_EFFECTIVE_RELATIONS)
        )
        effective_values = dict(dual.OBSERVER_EXPECTED_EFFECTIVE_PROPERTIES)
        effective_values.update(effective or {})
        output += "".join(
            f"{name}={effective_values[name]}\n"
            for name in sorted(dual.OBSERVER_EXPECTED_EFFECTIVE_PROPERTIES)
        )
        set_values = {
            "ReadWritePaths": str(
                core.HOME / ".local/state/grabowski/safety-observer"
            ),
            "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        }
        set_values.update(effective_sets or {})
        output += "".join(
            f"{name}={set_values[name]}\n"
            for name in sorted(dual.OBSERVER_EXPECTED_EFFECTIVE_SETS)
        )
        effective_after = after or (
            "basic.target " + " ".join(dual.OBSERVER_EXPECTED_AFTER)
        )
        effective_exec_start = exec_start or (
            "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 "
            f"{core.HOME}/.local/libexec/grabowski-safety-observer.py collect ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; "
            "code=(null) ; status=0/0 }"
        )
        return (
            output
            + f"After={effective_after}\n"
            + f"ExecStart={effective_exec_start}\n"
            + f"FragmentPath={target}\n"
            + f"DropInPaths={drop_ins}\n"
        )

    def run_systemctl(self, target: Path, **show_kwargs):
        def run(argv, **kwargs):
            if argv[:3] == ["systemctl", "--user", "daemon-reload"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if argv[:4] == [
                "systemctl",
                "--user",
                "start",
                target.name,
            ]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if argv[:4] == [
                "systemctl",
                "--user",
                "show",
                target.name,
            ]:
                if "--property=Result" in argv:
                    return SimpleNamespace(
                        returncode=0,
                        stdout=(
                            "Result=success\n"
                            "ActiveState=inactive\n"
                            "SubState=dead\n"
                        ),
                        stderr="",
                    )
                return SimpleNamespace(
                    returncode=0,
                    stdout=self.show_output(target, **show_kwargs),
                    stderr="",
                )
            self.fail(f"unexpected command: {argv}")

        return run

    def test_repository_unit_is_order_only(self) -> None:
        self.assertEqual(dual.OBSERVER_FORBIDDEN_RELATIONS, self.EXPECTED_RELATIONS)
        self.assertEqual(dual.OBSERVER_HIDDEN_RELATIONS, {"Upholds"})
        self.assertEqual(dual._validate_observer_unit_bytes(self.expected), self.expected)
        self.assertNotIn(b"RemainAfterExit", self.expected)
        self.assertNotIn(b"PrivateUsers", self.expected)
        self.assertNotIn(b"SystemCallFilter", self.expected)

    def test_repository_unit_has_exact_bounds_and_compatible_hardening(self) -> None:
        expected_service = dual.OBSERVER_EXPECTED_DIRECTIVES["Service"]
        self.assertEqual(expected_service["TimeoutStartSec"], "60")
        self.assertEqual(expected_service["MemoryMax"], "512M")
        self.assertEqual(expected_service["TasksMax"], "50")
        self.assertEqual(
            {
                name: expected_service[name]
                for name in (
                    "ProtectKernelTunables",
                    "ProtectControlGroups",
                    "RestrictNamespaces",
                    "SystemCallArchitectures",
                )
            },
            {
                "ProtectKernelTunables": "true",
                "ProtectControlGroups": "true",
                "RestrictNamespaces": "true",
                "SystemCallArchitectures": "native",
            },
        )
        for directive in dual.OBSERVER_USER_CAPABILITY_INCOMPATIBLE_DIRECTIVES:
            self.assertNotIn(directive, expected_service)
            self.assertNotIn(directive, dual.OBSERVER_EXPECTED_EFFECTIVE_PROPERTIES)
            self.assertNotIn(f"{directive}=".encode(), self.expected)

    def test_comments_cannot_spoof_after_or_exec_start(self) -> None:
        cases = {
            "comment": self.expected.replace(
                b"After=grabowski-operator.service tunnel-client-grabowski.service",
                b"# After=grabowski-operator.service tunnel-client-grabowski.service",
            ),
            "substring": self.expected.replace(
                b"ExecStart=/usr/bin/python3",
                b"NotExecStart=/usr/bin/python3",
            ),
        }
        for name, spoofed in cases.items():
            with self.subTest(name=name), self.assertRaises(core.DeployError):
                dual._validate_observer_unit_bytes(spoofed)

    def test_comment_line_continuation_is_rejected_before_comment_handling(self) -> None:
        candidate = self.expected.replace(
            b"[Service]\n",
            b"[Service]\n# harmless-looking comment \\\n",
        )
        with self.assertRaisesRegex(core.DeployError, "Zeilenfortsetzungen"):
            dual._validate_observer_unit_bytes(candidate)

    def test_unknown_duplicate_install_and_unexpected_values_are_rejected(self) -> None:
        cases = {
            "unknown_section": self.expected + b"[Timer]\nOnCalendar=hourly\n",
            "duplicate_directive": self.expected.replace(
                b"Description=Grabowski safety and connector incident observer\n",
                b"Description=Grabowski safety and connector incident observer\n"
                b"Description=Grabowski safety and connector incident observer\n",
            ),
            "duplicate_section": self.expected + b"[Unit]\n",
            "unexpected_value": self.expected.replace(
                b"MemoryMax=512M", b"MemoryMax=513M"
            ),
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaises(core.DeployError):
                dual._validate_observer_unit_bytes(candidate)

    def test_install_directives_are_never_allowed_in_active_sections(self) -> None:
        for directive in ("WantedBy", "RequiredBy", "Alias", "Also"):
            candidate = self.expected.replace(
                b"\n\n[Service]",
                f"\n{directive}=default.target\n\n[Service]".encode(),
            )
            with self.subTest(directive=directive), self.assertRaisesRegex(
                core.DeployError, "nicht erlaubte aktive Direktive"
            ):
                dual._validate_observer_unit_bytes(candidate)
        install_section = self.expected + b"[Install]\nWantedBy=default.target\n"
        with self.assertRaisesRegex(core.DeployError, "nicht erlaubten Abschnitt"):
            dual._validate_observer_unit_bytes(install_section)

    def test_all_systemd_249_coupling_relations_are_rejected_in_fragment(self) -> None:
        for relation in self.EXPECTED_RELATIONS:
            with self.subTest(relation=relation):
                candidate = self.expected.replace(
                    b"\n\n[Service]",
                    f"\n{relation}={dual.OPERATOR_SERVICE}\n\n[Service]".encode(),
                )
                with self.assertRaisesRegex(
                    core.DeployError, "nicht erlaubte aktive Direktive"
                ):
                    dual._validate_observer_unit_bytes(candidate)

    def test_hidden_upholds_is_not_requested_but_exact_fragment_and_no_dropins_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            with mock.patch.object(
                core,
                "run",
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout=self.show_output(target),
                    stderr="",
                ),
            ) as command:
                relations = dual._observer_unit_relations(target)
            argv = command.call_args.args[0]
            self.assertNotIn("--property=Upholds", argv)
            for name in dual.OBSERVER_EXPECTED_EFFECTIVE_PROPERTIES:
                self.assertIn(f"--property={name}", argv)
            for name in dual.OBSERVER_EXPECTED_EFFECTIVE_SETS:
                self.assertIn(f"--property={name}", argv)
            self.assertEqual(
                relations,
                {name: [] for name in dual.OBSERVER_EFFECTIVE_RELATIONS},
            )

    def test_dropins_are_rejected_for_hidden_relation_safety(self) -> None:
        target = Path("/tmp/grabowski-safety-observer.service")
        with mock.patch.object(
            core,
            "run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout=self.show_output(target, drop_ins="/run/user/drop-in.conf"),
                stderr="",
            ),
        ):
            with self.assertRaisesRegex(core.DeployError, "Drop-ins"):
                dual._observer_unit_relations(target)

    def test_effective_relation_after_and_exec_start_are_verified(self) -> None:
        target = Path("/tmp/grabowski-safety-observer.service")
        cases = {
            "relation": {
                "relations": {"StopPropagatedFrom": dual.TUNNEL_SERVICE},
            },
            "after": {"after": "basic.target"},
            "exec": {
                "exec_start": (
                    "{ path=/usr/bin/false ; argv[]=/usr/bin/false ; "
                    "ignore_errors=no }"
                ),
            },
        }
        for name, show_kwargs in cases.items():
            with self.subTest(name=name), mock.patch.object(
                core,
                "run",
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout=self.show_output(target, **show_kwargs),
                    stderr="",
                ),
            ):
                with self.assertRaises(core.DeployError):
                    dual._observer_unit_relations(target)

    def test_effective_bounds_and_hardening_are_verified(self) -> None:
        target = Path("/tmp/grabowski-safety-observer.service")
        properties = (
            "RemainAfterExit",
            "TimeoutStartUSec",
            "MemoryMax",
            "TasksMax",
            "UMask",
            "ProtectKernelTunables",
            "ProtectControlGroups",
            "RestrictNamespaces",
            "SystemCallArchitectures",
        )
        for name in properties:
            with self.subTest(property=name), mock.patch.object(
                core,
                "run",
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout=self.show_output(target, effective={name: "unexpected"}),
                    stderr="",
                ),
            ):
                with self.assertRaisesRegex(
                    core.DeployError, "Ausführungsgrenzen oder Härtung"
                ):
                    dual._observer_unit_relations(target)

    def test_effective_path_and_address_sets_are_verified_semantically(self) -> None:
        target = Path("/tmp/grabowski-safety-observer.service")
        with mock.patch.object(
            core,
            "run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout=self.show_output(
                    target,
                    effective_sets={
                        "RestrictAddressFamilies": "AF_INET6 AF_UNIX AF_INET",
                    },
                ),
                stderr="",
            ),
        ):
            dual._observer_unit_relations(target)
        for property_name in dual.OBSERVER_EXPECTED_EFFECTIVE_SETS:
            with self.subTest(property=property_name), mock.patch.object(
                core,
                "run",
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout=self.show_output(
                        target,
                        effective_sets={property_name: "unexpected"},
                    ),
                    stderr="",
                ),
            ):
                with self.assertRaisesRegex(core.DeployError, "Pfad- oder Adressgrenzen"):
                    dual._observer_unit_relations(target)

    def test_observer_helpers_have_no_unreachable_assertion_raises(self) -> None:
        source = (ROOT / "tools/deploy_runtime_dual.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        observer_helpers = {
            "_parse_observer_unit_directives",
            "_observer_unit_bytes",
            "_parse_effective_exec_start",
            "_require_parent_mapping",
            "_read_observer_unit_at",
            "install_safety_observer_unit",
        }

        def is_core_fail(statement: ast.stmt) -> bool:
            return (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Attribute)
                and isinstance(statement.value.func.value, ast.Name)
                and statement.value.func.value.id == "core"
                and statement.value.func.attr == "fail"
            )

        def raises_assertion(statement: ast.stmt) -> bool:
            if not isinstance(statement, ast.Raise) or statement.exc is None:
                return False
            expression = statement.exc
            if isinstance(expression, ast.Call):
                expression = expression.func
            return isinstance(expression, ast.Name) and expression.id == "AssertionError"

        offenders: set[tuple[str, int]] = set()
        for function in module.body:
            if not isinstance(function, ast.FunctionDef) or function.name not in observer_helpers:
                continue
            for node in ast.walk(function):
                for _field, value in ast.iter_fields(node):
                    if not isinstance(value, list):
                        continue
                    for current, following in zip(value, value[1:]):
                        if is_core_fail(current) and raises_assertion(following):
                            offenders.add((function.name, following.lineno))
        self.assertEqual(offenders, set())

    def test_install_uses_commit_blob_not_mutable_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            source = repo / dual.SAFETY_OBSERVER_UNIT_RELATIVE
            source.parent.mkdir(parents=True)
            source.write_bytes(b"mutable and untrusted\n")
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"old\n")
            with (
                mock.patch.object(core, "git_show", return_value=self.expected) as git_show,
                mock.patch.object(
                    core,
                    "run",
                    side_effect=self.run_systemctl(target),
                ),
            ):
                result = dual.install_safety_observer_unit(
                    repo,
                    self.snapshot,
                    target=target,
                )
            git_show.assert_called_once_with(
                repo,
                self.snapshot.repo_head,
                dual.SAFETY_OBSERVER_UNIT_RELATIVE,
            )
            self.assertEqual(target.read_bytes(), self.expected)
            self.assertEqual(result["repo_head"], self.snapshot.repo_head)
            retained = self.retained_paths(target)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), b"old\n")
            self.assertEqual(result["retained_path"], str(retained[0]))

    def test_install_repairs_noncanonical_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            target.write_bytes(self.expected)
            target.chmod(0o600)
            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(core, "run", side_effect=self.run_systemctl(target)),
            ):
                result = dual.install_safety_observer_unit(
                    repo,
                    self.snapshot,
                    target=target,
                )

            self.assertTrue(result["changed"])
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            retained = self.retained_paths(target)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), self.expected)
            self.assertEqual(retained[0].stat().st_mode & 0o777, 0o600)

    def test_install_rejects_symlink_and_hardlink_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            parent = root / "config/systemd/user"
            parent.mkdir(parents=True)
            victim = root / "victim"
            victim.write_bytes(b"victim\n")
            targets = {
                "symlink": parent / "symlink.service",
                "hardlink": parent / "hardlink.service",
            }
            targets["symlink"].symlink_to(victim)
            targets["hardlink"].hardlink_to(victim)
            for kind, target in targets.items():
                with self.subTest(kind=kind), mock.patch.object(
                    core,
                    "git_show",
                    return_value=self.expected,
                ):
                    with self.assertRaises(core.DeployError):
                        dual.install_safety_observer_unit(
                            repo,
                            self.snapshot,
                            target=target,
                        )
            self.assertEqual(victim.read_bytes(), b"victim\n")

    def test_disallowed_control_bytes_are_rejected(self) -> None:
        cases = {
            "null": b"\x00",
            "vertical_tab": b"\x0b",
            "form_feed": b"\x0c",
            "carriage_return": b"\x0d",
            "delete": b"\x7f",
        }
        for name, byte in cases.items():
            candidate = self.expected.replace(
                b"After=grabowski-operator.service tunnel-client-grabowski.service\n",
                b"After=grabowski-operator.service tunnel-client-grabowski.service"
                + byte
                + b"\n",
            )
            with self.subTest(name=name), self.assertRaises(core.DeployError):
                dual._validate_observer_unit_bytes(candidate)

    def test_vertical_tab_before_after_directive_is_rejected(self) -> None:
        candidate = self.expected.replace(b"\nAfter=", b"\n\x0bAfter=")
        with self.assertRaises(core.DeployError):
            dual._validate_observer_unit_bytes(candidate)

    def test_crlf_line_endings_are_rejected(self) -> None:
        candidate = self.expected.replace(b"\n", b"\r\n")
        with self.assertRaises(core.DeployError):
            dual._validate_observer_unit_bytes(candidate)

    def test_comment_cannot_be_spoofed_via_control_byte(self) -> None:
        candidate = self.expected.replace(
            b"[Service]\n",
            b"[Service]\n#\x0bWantedBy=default.target\n",
        )
        with self.assertRaises(core.DeployError):
            dual._validate_observer_unit_bytes(candidate)

    def test_directive_cannot_smuggle_trailing_content_via_form_feed(self) -> None:
        candidate = self.expected.replace(
            b"TasksMax=50\n",
            b"TasksMax=50\x0cWants=malicious.service\n",
        )
        with self.assertRaises(core.DeployError):
            dual._validate_observer_unit_bytes(candidate)

    def test_renameat2_wrapper_fails_closed_on_enosys(self) -> None:
        def fake(*_args: object) -> int:
            ctypes.set_errno(errno.ENOSYS)
            return -1

        with mock.patch.object(dual, "_RENAMEAT2", fake):
            with self.assertRaisesRegex(core.DeployError, "renameat2"):
                dual._renameat2(0, "a", 0, "b", dual.RENAME_EXCHANGE)

    def test_renameat2_wrapper_fails_closed_when_unavailable(self) -> None:
        with mock.patch.object(dual, "_RENAMEAT2", None):
            with self.assertRaisesRegex(core.DeployError, "renameat2"):
                dual._renameat2(0, "a", 0, "b", dual.RENAME_EXCHANGE)

    def test_renameat2_wrapper_raises_oserror_for_generic_errno(self) -> None:
        def fake(*_args: object) -> int:
            ctypes.set_errno(errno.EACCES)
            return -1

        with mock.patch.object(dual, "_RENAMEAT2", fake):
            with self.assertRaises(OSError):
                dual._renameat2(0, "a", 0, "b", dual.RENAME_NOREPLACE)

    def test_install_fails_closed_when_renameat2_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"old\n")
            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(dual, "_RENAMEAT2", None),
            ):
                with self.assertRaisesRegex(core.DeployError, "renameat2"):
                    dual.install_safety_observer_unit(
                        repo, self.snapshot, target=target
                    )
            self.assertEqual(target.read_bytes(), b"old\n")
            incoming = self.incoming_paths(target)
            self.assertEqual(len(incoming), 1)
            self.assertEqual(incoming[0].read_bytes(), self.expected)

    def test_install_detects_injection_at_atomic_boundary_for_existing_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"old\n")
            replacement = target.with_name("replacement-existing.service")
            injected = b"raced\n"
            replacement.write_bytes(injected)

            real_renameat2 = dual._renameat2
            triggered: list[str] = []

            def spy(old_dir_fd, old_name, new_dir_fd, new_name, flags):
                if flags == dual.RENAME_EXCHANGE and not triggered:
                    triggered.append("inject")
                    replacement.replace(target)
                return real_renameat2(old_dir_fd, old_name, new_dir_fd, new_name, flags)

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(dual, "_renameat2", side_effect=spy),
            ):
                with self.assertRaisesRegex(core.DeployError, "driftete"):
                    dual.install_safety_observer_unit(
                        repo, self.snapshot, target=target
                    )

            self.assertEqual(triggered, ["inject"])
            self.assertEqual(target.read_bytes(), self.expected)
            retained = self.retained_paths(target)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), injected)
            self.assertEqual(self.incoming_paths(target), [])

    def test_install_fails_on_concurrent_creation_at_atomic_boundary_for_absent_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            injected = b"concurrently-created\n"

            real_renameat2 = dual._renameat2
            triggered: list[str] = []

            def spy(old_dir_fd, old_name, new_dir_fd, new_name, flags):
                if flags == dual.RENAME_NOREPLACE and not triggered:
                    triggered.append("inject")
                    descriptor = os.open(
                        new_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o644,
                        dir_fd=new_dir_fd,
                    )
                    try:
                        os.write(descriptor, injected)
                    finally:
                        os.close(descriptor)
                return real_renameat2(old_dir_fd, old_name, new_dir_fd, new_name, flags)

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(dual, "_renameat2", side_effect=spy),
            ):
                with self.assertRaises(core.DeployError):
                    dual.install_safety_observer_unit(
                        repo, self.snapshot, target=target
                    )

            self.assertEqual(triggered, ["inject"])
            self.assertEqual(target.read_bytes(), injected)
            incoming = self.incoming_paths(target)
            self.assertEqual(len(incoming), 1)
            self.assertEqual(incoming[0].read_bytes(), self.expected)

    def test_install_detects_target_replacement_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"old\n")
            replacement = target.with_name("replacement.service")
            replacement.write_bytes(b"raced\n")
            calls = 0

            def token(*_args) -> str:
                nonlocal calls
                calls += 1
                if calls == 1:
                    replacement.replace(target)
                    return "incoming-fixed"
                return "retained-fixed"

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(dual.secrets, "token_hex", side_effect=token),
            ):
                with self.assertRaisesRegex(core.DeployError, "driftete"):
                    dual.install_safety_observer_unit(
                        repo,
                        self.snapshot,
                        target=target,
                    )

            self.assertEqual(target.read_bytes(), self.expected)
            retained = self.retained_paths(target)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), b"raced\n")

    def test_second_target_replacement_is_never_exchanged_back_or_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            original = b"old\n"
            third = b"third-party\n"
            target.write_bytes(original)
            third_path = target.with_name("third.service")
            third_path.write_bytes(third)
            real_renameat2 = dual._renameat2
            calls = 0

            def spy(old_dir_fd, old_name, new_dir_fd, new_name, flags):
                nonlocal calls
                calls += 1
                if calls == 2:
                    self.assertEqual(flags, dual.RENAME_NOREPLACE)
                    third_path.replace(target)
                return real_renameat2(
                    old_dir_fd,
                    old_name,
                    new_dir_fd,
                    new_name,
                    flags,
                )

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(dual, "_renameat2", side_effect=spy),
            ):
                with self.assertRaisesRegex(core.DeployError, "Ziel driftete"):
                    dual.install_safety_observer_unit(
                        repo,
                        self.snapshot,
                        target=target,
                    )

            self.assertEqual(calls, 2)
            self.assertEqual(target.read_bytes(), third)
            retained = self.retained_paths(target)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), original)
            self.assertEqual(self.incoming_paths(target), [])

    def test_displaced_name_replacement_is_retained_without_cleanup_unlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"old\n")
            attacker = target.with_name("attacker.service")
            attacker.write_bytes(b"attacker\n")
            real_renameat2 = dual._renameat2
            calls = 0

            def spy(old_dir_fd, old_name, new_dir_fd, new_name, flags):
                nonlocal calls
                calls += 1
                if calls == 2:
                    attacker.replace(target.parent / old_name)
                return real_renameat2(
                    old_dir_fd,
                    old_name,
                    new_dir_fd,
                    new_name,
                    flags,
                )

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(dual, "_renameat2", side_effect=spy),
            ):
                with self.assertRaisesRegex(core.DeployError, "Verdrängte"):
                    dual.install_safety_observer_unit(
                        repo,
                        self.snapshot,
                        target=target,
                    )

            self.assertEqual(target.read_bytes(), self.expected)
            retained = self.retained_paths(target)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), b"attacker\n")
            self.assertEqual(self.incoming_paths(target), [])

    def test_install_detects_parent_mapping_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            parent = root / "config/systemd/user"
            target = parent / "grabowski-safety-observer.service"
            parent.mkdir(parents=True)
            target.write_bytes(b"old\n")
            moved_parent = root / "moved-user"

            def replace_parent(*_args) -> str:
                parent.rename(moved_parent)
                parent.mkdir()
                return "fixed-token"

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(dual.secrets, "token_hex", side_effect=replace_parent),
            ):
                with self.assertRaisesRegex(core.DeployError, "Verzeichnis driftete"):
                    dual.install_safety_observer_unit(
                        repo,
                        self.snapshot,
                        target=target,
                    )

    def test_install_rejects_intermediate_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            real_config = root / "real-config"
            (real_config / "systemd/user").mkdir(parents=True)
            (root / "config").symlink_to(real_config, target_is_directory=True)
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            with mock.patch.object(core, "git_show", return_value=self.expected):
                with self.assertRaisesRegex(core.DeployError, "Verzeichniskomponente"):
                    dual.install_safety_observer_unit(repo, self.snapshot, target=target)

    def test_install_detects_intermediate_mapping_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            config = root / "config"
            parent = config / "systemd/user"
            target = parent / "grabowski-safety-observer.service"
            parent.mkdir(parents=True)
            target.write_bytes(b"old\n")
            moved_config = root / "moved-config"

            def replace_intermediate(*_args) -> str:
                config.rename(moved_config)
                (config / "systemd/user").mkdir(parents=True)
                return "fixed-token"

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(dual.secrets, "token_hex", side_effect=replace_intermediate),
            ):
                with self.assertRaisesRegex(core.DeployError, "Verzeichniskette driftete"):
                    dual.install_safety_observer_unit(repo, self.snapshot, target=target)

    def test_install_rechecks_exact_target_after_effective_systemd_readback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"old\n")
            replacement = target.with_name("post-readback-replacement.service")
            replacement.write_bytes(b"post-readback-drift\n")

            def relations(_target: Path):
                replacement.replace(target)
                return {
                    name: []
                    for name in dual.OBSERVER_EFFECTIVE_RELATIONS
                }

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(
                    core,
                    "run",
                    return_value=SimpleNamespace(
                        returncode=0,
                        stdout="",
                        stderr="",
                    ),
                ),
                mock.patch.object(
                    dual,
                    "_observer_unit_relations",
                    side_effect=relations,
                ),
                mock.patch.object(
                    dual,
                    "_verify_safety_observer_executes",
                    return_value={
                        "Result": "success",
                        "ActiveState": "inactive",
                        "SubState": "dead",
                    },
                ),
            ):
                with self.assertRaisesRegex(
                    core.DeployError,
                    "systemd-Readbacks",
                ):
                    dual.install_safety_observer_unit(
                        repo,
                        self.snapshot,
                        target=target,
                    )

            self.assertEqual(target.read_bytes(), b"post-readback-drift\n")
            retained = self.retained_paths(target)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), b"old\n")

    def test_install_fails_closed_when_observer_cannot_execute(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/grabowski-safety-observer.service"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"old\n")
            base_run = self.run_systemctl(target)

            def run(argv, **kwargs):
                if argv[:4] == [
                    "systemctl",
                    "--user",
                    "start",
                    dual.SAFETY_OBSERVER_SERVICE,
                ]:
                    return SimpleNamespace(
                        returncode=218,
                        stdout="",
                        stderr="CAPABILITIES",
                    )
                return base_run(argv, **kwargs)

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(core, "run", side_effect=run),
            ):
                with self.assertRaisesRegex(
                    core.DeployError,
                    "nicht erfolgreich ausgeführt",
                ):
                    dual.install_safety_observer_unit(
                        repo,
                        self.snapshot,
                        target=target,
                    )

            self.assertEqual(target.read_bytes(), self.expected)

    def test_observer_execution_readback_must_be_inactive_success(self) -> None:
        responses = [
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(
                returncode=0,
                stdout=(
                    "Result=exit-code\n"
                    "ActiveState=failed\n"
                    "SubState=failed\n"
                ),
                stderr="",
            ),
        ]
        with mock.patch.object(core, "run", side_effect=responses):
            with self.assertRaisesRegex(
                core.DeployError,
                "nicht kanonisch erfolgreich",
            ):
                dual._verify_safety_observer_executes(dual.SAFETY_OBSERVER_SERVICE)

    def test_observer_execution_uses_requested_unit_and_query_timeout(self) -> None:
        unit_name = "custom-safety-observer.service"
        responses = [
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(
                returncode=0,
                stdout=(
                    "Result=success\n"
                    "ActiveState=inactive\n"
                    "SubState=dead\n"
                ),
                stderr="",
            ),
        ]
        with mock.patch.object(core, "run", side_effect=responses) as run:
            result = dual._verify_safety_observer_executes(unit_name)

        self.assertEqual(
            result,
            {
                "Result": "success",
                "ActiveState": "inactive",
                "SubState": "dead",
            },
        )
        self.assertEqual(
            run.call_args_list,
            [
                mock.call(
                    ["systemctl", "--user", "start", unit_name],
                    check=False,
                    capture=True,
                    timeout=core.TIMEOUTS["service_start"],
                ),
                mock.call(
                    [
                        "systemctl",
                        "--user",
                        "show",
                        unit_name,
                        "--property=Result",
                        "--property=ActiveState",
                        "--property=SubState",
                    ],
                    check=False,
                    capture=True,
                    timeout=core.TIMEOUTS["systemd_query"],
                ),
            ],
        )

    def test_observer_execution_start_failure_preserves_stderr(self) -> None:
        with mock.patch.object(
            core,
            "run",
            return_value=SimpleNamespace(
                returncode=218,
                stdout="",
                stderr="Failed to drop capabilities\n",
            ),
        ):
            with self.assertRaises(core.DeployError) as raised:
                dual._verify_safety_observer_executes(
                    dual.SAFETY_OBSERVER_SERVICE,
                )

        self.assertEqual(raised.exception.phase, "observer-unit-execution")
        self.assertEqual(
            raised.exception.details,
            {
                "returncode": 218,
                "stderr": "Failed to drop capabilities",
            },
        )

    def test_observer_execution_status_failure_preserves_stderr(self) -> None:
        responses = [
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="Failed to query unit state\n",
            ),
        ]
        with mock.patch.object(core, "run", side_effect=responses):
            with self.assertRaises(core.DeployError) as raised:
                dual._verify_safety_observer_executes(
                    dual.SAFETY_OBSERVER_SERVICE,
                )

        self.assertEqual(
            raised.exception.phase,
            "observer-unit-execution-readback",
        )
        self.assertEqual(
            raised.exception.details,
            {
                "returncode": 1,
                "stderr": "Failed to query unit state",
            },
        )

    def test_observer_relation_readback_uses_requested_unit_and_query_timeout(self) -> None:
        target = Path("/tmp/custom-safety-observer.service")
        with mock.patch.object(
            core,
            "run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout=self.show_output(target),
                stderr="",
            ),
        ) as run:
            dual._observer_unit_relations(target)

        argv = run.call_args.args[0]
        self.assertEqual(
            argv[:4],
            ["systemctl", "--user", "show", target.name],
        )
        self.assertEqual(
            run.call_args.kwargs["timeout"],
            core.TIMEOUTS["systemd_query"],
        )

    def test_observer_relation_readback_failure_preserves_stderr(self) -> None:
        target = Path("/tmp/custom-safety-observer.service")
        with mock.patch.object(
            core,
            "run",
            return_value=SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="Failed to read unit properties\n",
            ),
        ):
            with self.assertRaises(core.DeployError) as raised:
                dual._observer_unit_relations(target)

        self.assertEqual(raised.exception.phase, "observer-unit-readback")
        self.assertEqual(
            raised.exception.details,
            {
                "returncode": 1,
                "stderr": "Failed to read unit properties",
            },
        )

    def test_install_validates_requested_target_unit_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            target = root / "config/systemd/user/custom-safety-observer.service"
            target.parent.mkdir(parents=True)

            with (
                mock.patch.object(core, "git_show", return_value=self.expected),
                mock.patch.object(core, "run", side_effect=self.run_systemctl(target)),
            ):
                result = dual.install_safety_observer_unit(
                    repo,
                    self.snapshot,
                    target=target,
                )

            self.assertTrue(result["changed"])
            self.assertEqual(result["path"], str(target))
            self.assertEqual(
                result["execution"],
                {
                    "Result": "success",
                    "ActiveState": "inactive",
                    "SubState": "dead",
                },
            )

    def test_incomplete_effective_relation_readback_fails_closed(self) -> None:
        target = Path("/tmp/grabowski-safety-observer.service")
        output = self.show_output(target).replace("Wants=\n", "")
        with mock.patch.object(
            core,
            "run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout=output,
                stderr="",
            ),
        ):
            with self.assertRaisesRegex(
                core.DeployError,
                "Relationen konnten nicht vollständig gelesen werden",
            ):
                dual._observer_unit_relations(target)

    def test_main_keeps_installation_inside_locked_deploy_flow(self) -> None:
        events: list[str] = []
        args = SimpleNamespace(
            repo=ROOT,
            runtime=RUNTIME,
            profile_path=Path("profile.yaml"),
            lock_file=Path("deploy.lock"),
            timeout=1,
            check=False,
            preflight=False,
            apply=True,
        )
        with (
            mock.patch.object(dual, "parse_args", return_value=args),
            mock.patch.object(core, "absolute_no_resolve", side_effect=lambda value: value),
            mock.patch.object(
                dual,
                "preflight_url",
                side_effect=lambda *args, **kwargs: events.append("preflight"),
            ),
            mock.patch.object(
                core,
                "deployment_lock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch.object(dual, "install_safety_observer_unit") as install,
            mock.patch.object(
                dual,
                "deploy_url",
                side_effect=lambda *args, **kwargs: events.append("deploy"),
            ),
        ):
            result = dual.main()
        self.assertEqual(result, 0)
        self.assertEqual(events, ["preflight", "deploy"])
        install.assert_not_called()


class DeploymentSequenceTests(unittest.TestCase):
    def snapshot(self):
        return SimpleNamespace(
            contract=CONTRACT,
            repo_head="a" * 40,
            source_sha256="b" * 64,
            runtime_lock_sha256="c" * 64,
        )

    def build(self):
        return SimpleNamespace(
            release_path=Path("/release/new"),
            release_id="new",
            protocol_version="2025-06-18",
            agent_instructions=TEST_AGENT_INSTRUCTIONS_IDENTITY,
        )

    def test_url_preflight_requires_operator_listener(self) -> None:
        events: list[str] = []
        snapshot = self.snapshot()
        topology = dual.ProfileTopology("url", server_url_count=1)
        with (
            mock.patch.object(core, "snapshot_from_git", return_value=snapshot),
            mock.patch.object(core, "require_runtime_replaceable", return_value=RUNTIME),
            mock.patch.object(dual, "profile_topology", return_value=topology),
            mock.patch.object(dual, "require_topology_matches_contract"),
            mock.patch.object(
                dual,
                "require_service_active",
                side_effect=lambda unit: events.append(f"active:{unit}") or observation(True),
            ),
            mock.patch.object(
                dual,
                "verify_operator_process",
                side_effect=lambda *args, **kwargs: events.append("verify:operator") or {"pid": 1},
            ),
            mock.patch.object(
                dual,
                "require_operator_listener",
                side_effect=lambda **kwargs: events.append("listener") or {"successful_samples": 2},
            ),
            mock.patch.object(
                dual,
                "verify_tunnel_process",
                side_effect=lambda: events.append("verify:tunnel") or {"pid": 2},
            ),
        ):
            result = dual.preflight_url(ROOT, RUNTIME, Path("profile.yaml"))
        self.assertEqual(result, (snapshot, RUNTIME, topology))
        self.assertEqual(
            events,
            [
                f"active:{dual.OPERATOR_SERVICE}",
                f"active:{dual.TUNNEL_SERVICE}",
                "verify:operator",
                "listener",
                "verify:tunnel",
            ],
        )

    def test_url_runtime_identity_binds_expected_agent_instructions(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self.snapshot()
            with (
                mock.patch.object(core, "verify_manifest", return_value={}) as verify_manifest,
                mock.patch.object(core, "verify_final_release_artifacts"),
                mock.patch.object(
                    dual,
                    "verify_operator_process",
                    return_value={"pid": 1},
                ),
            ):
                dual.verify_url_runtime_identity(
                    release,
                    runtime,
                    CONTRACT,
                    snapshot=snapshot,
                    agent_instructions=TEST_AGENT_INSTRUCTIONS_IDENTITY,
                )
            verify_manifest.assert_called_once_with(
                release,
                snapshot=snapshot,
                stable_runtime=runtime,
                expected_agent_instructions=TEST_AGENT_INSTRUCTIONS_IDENTITY,
            )

    def test_cutover_order_is_tunnel_then_operator_and_reverse_on_start(self) -> None:
        events: list[str] = []
        snapshot = self.snapshot()
        active = observation(True)
        ready = dual.DualReadiness(True, active, active, "live", "ready")
        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(snapshot, RUNTIME, dual.ProfileTopology("url", server_url_count=1)),
            ),
            mock.patch.object(core, "build_release", return_value=self.build()),
            mock.patch.object(
                core,
                "verify_apply_snapshot_unchanged",
                side_effect=lambda *args: events.append("verify:snapshot"),
            ),
            mock.patch.object(
                core,
                "verify_manifest",
                side_effect=lambda *args, **kwargs: events.append("verify:manifest"),
            ),
            mock.patch.object(core, "capture_pointer", return_value=SimpleNamespace()),
            mock.patch.object(
                dual,
                "install_safety_observer_unit",
                side_effect=lambda *args: events.append("install:observer"),
            ) as install,
            mock.patch.object(
                dual,
                "stop_service",
                side_effect=lambda unit: events.append(f"stop:{unit}") or observation(False),
            ),
            mock.patch.object(
                dual,
                "start_service",
                side_effect=lambda unit: events.append(f"start:{unit}") or active,
            ),
            mock.patch.object(
                dual,
                "profile_topology",
                return_value=dual.ProfileTopology("url", server_url_count=1),
            ),
            mock.patch.object(dual, "require_topology_matches_contract"),
            mock.patch.object(
                core,
                "activate_pointer",
                side_effect=lambda activation: events.append("activate"),
            ),
            mock.patch.object(
                dual,
                "verify_operator_process",
                side_effect=lambda *args, **kwargs: events.append("verify:operator") or {"pid": 1},
            ),
            mock.patch.object(
                dual,
                "require_operator_listener",
                side_effect=lambda **kwargs: events.append("listener") or {"successful_samples": 2},
            ),
            mock.patch.object(
                dual,
                "verify_tunnel_process",
                side_effect=lambda: events.append("verify:tunnel") or {"pid": 2},
            ),
            mock.patch.object(dual, "wait_until_ready", return_value=ready),
            mock.patch.object(
                dual,
                "verify_url_runtime_identity",
                return_value={"process": {"pid": 1}},
            ),
        ):
            dual.deploy_url(ROOT, RUNTIME, Path("profile.yaml"), timeout_seconds=1)
        self.assertEqual(
            events,
            [
                "verify:snapshot",
                "verify:manifest",
                "install:observer",
                "verify:snapshot",
                f"stop:{dual.TUNNEL_SERVICE}",
                f"stop:{dual.OPERATOR_SERVICE}",
                "verify:snapshot",
                "activate",
                f"start:{dual.OPERATOR_SERVICE}",
                "verify:operator",
                "listener",
                f"start:{dual.TUNNEL_SERVICE}",
                "verify:tunnel",
            ],
        )
        install.assert_called_once_with(ROOT, snapshot)

    def test_legacy_stdio_deploy_never_installs_observer_unit(self) -> None:
        snapshot = self.snapshot()
        topology = dual.ProfileTopology("legacy-stdio", legacy_entrypoint=CONTRACT)
        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(snapshot, RUNTIME, topology),
            ),
            mock.patch.object(core, "deploy") as deploy,
            mock.patch.object(core, "build_release") as build,
            mock.patch.object(dual, "install_safety_observer_unit") as install,
        ):
            dual.deploy_url(ROOT, RUNTIME, Path("profile.yaml"), timeout_seconds=1)
        deploy.assert_called_once_with(
            ROOT,
            RUNTIME,
            Path("profile.yaml"),
            timeout_seconds=1,
        )
        build.assert_not_called()
        install.assert_not_called()

    def test_operator_stop_failure_prevents_pointer_activation(self) -> None:
        events: list[str] = []
        stderr = io.StringIO()
        repair = {
            "changed": True,
            "repo_head": "a" * 40,
            "sha256": "d" * 64,
            "retained_path": "/tmp/observer.retained",
            "retained_sha256": "e" * 64,
        }

        def stop(unit: str):
            events.append(f"stop:{unit}")
            if unit == dual.OPERATOR_SERVICE:
                raise core.DeployError("operator stayed active")
            return observation(False)

        def rollback(*args, **kwargs):
            events.append("rollback")
            raise core.DeployError("rolled back")

        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(self.snapshot(), RUNTIME, dual.ProfileTopology("url", server_url_count=1)),
            ),
            mock.patch.object(core, "build_release", return_value=self.build()),
            mock.patch.object(core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(core, "verify_manifest"),
            mock.patch.object(core, "capture_pointer", return_value=SimpleNamespace()),
            mock.patch.object(
                dual, "install_safety_observer_unit", return_value=repair
            ),
            mock.patch.object(dual, "stop_service", side_effect=stop),
            mock.patch.object(core, "activate_pointer") as activate,
            mock.patch.object(dual, "rollback_url", side_effect=rollback),
            mock.patch("sys.stderr", stderr),
        ):
            with self.assertRaises(core.DeployError):
                dual.deploy_url(ROOT, RUNTIME, Path("profile.yaml"), timeout_seconds=1)
        activate.assert_not_called()
        self.assertEqual(
            events,
            [
                f"stop:{dual.TUNNEL_SERVICE}",
                f"stop:{dual.OPERATOR_SERVICE}",
                "rollback",
            ],
        )
        payload = json.loads(
            next(
                line.removeprefix("PRIMARY-DEPLOY-ERROR: ")
                for line in stderr.getvalue().splitlines()
                if line.startswith("PRIMARY-DEPLOY-ERROR: ")
            )
        )
        self.assertEqual(
            payload["observer_safety_repair"],
            {
                "marker": dual.OBSERVER_SAFETY_REPAIR_MARKER,
                "retained": True,
                **repair,
            },
        )

    def test_post_observer_snapshot_failure_retains_repair_and_rolls_back(self) -> None:
        stderr = io.StringIO()
        repair = {
            "changed": False,
            "repo_head": "a" * 40,
            "sha256": "d" * 64,
        }
        rollback_calls: list[str] = []

        def verify(*_args):
            if verify.calls:
                raise core.DeployError("snapshot drift")
            verify.calls += 1

        verify.calls = 0

        def rollback(*_args, **_kwargs):
            rollback_calls.append("rollback")
            raise core.DeployError("rolled back")

        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(
                    self.snapshot(),
                    RUNTIME,
                    dual.ProfileTopology("url", server_url_count=1),
                ),
            ),
            mock.patch.object(core, "build_release", return_value=self.build()),
            mock.patch.object(core, "verify_apply_snapshot_unchanged", side_effect=verify),
            mock.patch.object(core, "verify_manifest"),
            mock.patch.object(core, "capture_pointer", return_value=SimpleNamespace()),
            mock.patch.object(
                dual, "install_safety_observer_unit", return_value=repair
            ),
            mock.patch.object(dual, "stop_service") as stop,
            mock.patch.object(dual, "rollback_url", side_effect=rollback),
            mock.patch("sys.stderr", stderr),
        ):
            with self.assertRaises(core.DeployError):
                dual.deploy_url(ROOT, RUNTIME, Path("profile.yaml"), timeout_seconds=1)

        stop.assert_not_called()
        self.assertEqual(rollback_calls, ["rollback"])
        payload = json.loads(
            next(
                line.removeprefix("PRIMARY-DEPLOY-ERROR: ")
                for line in stderr.getvalue().splitlines()
                if line.startswith("PRIMARY-DEPLOY-ERROR: ")
            )
        )
        self.assertEqual(payload["deploy_phase"], "post-observer-snapshot-revalidation")
        self.assertEqual(
            payload["observer_safety_repair"],
            {
                "marker": dual.OBSERVER_SAFETY_REPAIR_MARKER,
                "retained": True,
                **repair,
            },
        )

    def test_primary_error_preserves_inner_phase_and_records_deploy_phase(self) -> None:
        stderr = io.StringIO()

        def stop(unit: str):
            if unit == dual.OPERATOR_SERVICE:
                raise core.DeployError(
                    "helper timed out",
                    phase="command-timeout",
                )
            return observation(False)

        def rollback(*args, **kwargs):
            raise core.DeployError("rolled back")

        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(
                    self.snapshot(),
                    RUNTIME,
                    dual.ProfileTopology("url", server_url_count=1),
                ),
            ),
            mock.patch.object(core, "build_release", return_value=self.build()),
            mock.patch.object(core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(core, "verify_manifest"),
            mock.patch.object(core, "capture_pointer", return_value=SimpleNamespace()),
            mock.patch.object(
                dual,
                "install_safety_observer_unit",
                return_value={
                    "changed": False,
                    "repo_head": "a" * 40,
                    "sha256": "d" * 64,
                },
            ),
            mock.patch.object(dual, "stop_service", side_effect=stop),
            mock.patch.object(dual, "rollback_url", side_effect=rollback),
            mock.patch("sys.stderr", stderr),
        ):
            with self.assertRaises(core.DeployError):
                dual.deploy_url(ROOT, RUNTIME, Path("profile.yaml"), timeout_seconds=1)

        error_line = next(
            line
            for line in stderr.getvalue().splitlines()
            if line.startswith("PRIMARY-DEPLOY-ERROR: ")
        )
        payload = json.loads(error_line.removeprefix("PRIMARY-DEPLOY-ERROR: "))

        self.assertEqual(payload["phase"], "command-timeout")
        self.assertEqual(payload["deploy_phase"], "stop-operator")

    def test_rollback_stops_both_restores_then_starts_operator_before_tunnel(self) -> None:
        events: list[str] = []
        active = observation(True)
        inactive = observation(False)
        ready = dual.DualReadiness(True, active, active, "live", "ready")
        activation = SimpleNamespace(
            runtime=RUNTIME,
            previous=SimpleNamespace(),
        )
        with (
            mock.patch.object(
                dual,
                "stop_service",
                side_effect=lambda unit: events.append(f"stop:{unit}") or inactive,
            ),
            mock.patch.object(
                core,
                "restore_pointer",
                side_effect=lambda value: events.append("restore") or value,
            ),
            mock.patch.object(
                core,
                "verify_pointer_state",
                side_effect=lambda *args: events.append("verify:pointer") or SimpleNamespace(),
            ),
            mock.patch.object(
                dual,
                "start_service",
                side_effect=lambda unit: events.append(f"start:{unit}") or active,
            ),
            mock.patch.object(
                dual,
                "verify_operator_process",
                side_effect=lambda *args, **kwargs: events.append("verify:operator") or {"pid": 1},
            ),
            mock.patch.object(
                dual,
                "require_operator_listener",
                side_effect=lambda **kwargs: events.append("listener") or {"successful_samples": 2},
            ),
            mock.patch.object(dual, "wait_until_ready", return_value=ready),
        ):
            with self.assertRaises(core.DeployError):
                dual.rollback_url(
                    core.DeployError("primary"),
                    activation=activation,
                    contract=CONTRACT,
                    timeout_seconds=1,
                )
        self.assertEqual(
            events,
            [
                f"stop:{dual.TUNNEL_SERVICE}",
                f"stop:{dual.OPERATOR_SERVICE}",
                "restore",
                "verify:pointer",
                f"start:{dual.OPERATOR_SERVICE}",
                "verify:operator",
                "listener",
                f"start:{dual.TUNNEL_SERVICE}",
            ],
        )


if __name__ == "__main__":
    unittest.main()
