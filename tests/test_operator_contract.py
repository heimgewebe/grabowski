from pathlib import Path
import ast
import json
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "grabowski_operator.py"


class OperatorContractTests(unittest.TestCase):
    def test_operator_source_compiles(self) -> None:
        tree = ast.parse(
            SOURCE.read_text(encoding="utf-8"),
            filename=str(SOURCE),
        )
        self.assertIsInstance(tree, ast.Module)

    def test_expected_tools_are_declared(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        declared = set()

        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                function = decorator.func
                if not (
                    isinstance(function, ast.Attribute)
                    and function.attr == "tool"
                ):
                    continue
                for keyword in decorator.keywords:
                    if (
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                    ):
                        declared.add(keyword.value.value)

        expected = {
            "grabowski_terminal_run",
            "grabowski_job_start",
            "grabowski_job_status",
            "grabowski_job_logs",
            "grabowski_job_cancel",
            "grabowski_git",
            "grabowski_github",
            "grabowski_user_service",
            "grabowski_tmux_list",
            "grabowski_tmux_capture",
            "grabowski_tmux_send",
            "grabowski_process_list",
            "grabowski_process_signal",
            "grabowski_ports",
        }
        self.assertEqual(expected, declared)

    def test_policy_no_longer_forbids_operator_core(self) -> None:
        policy = json.loads(
            (
                ROOT / "config" / "access.example.json"
            ).read_text(encoding="utf-8")
        )
        forbidden = set(policy["forbidden_capabilities"])
        self.assertNotIn("shell_execute", forbidden)
        self.assertNotIn("git_mutate", forbidden)
        self.assertNotIn("service_control", forbidden)

    def test_privilege_escalation_is_explicitly_blocked(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        for command in ("sudo", "su", "pkexec", "doas"):
            self.assertIn(command, source)

    def test_evidence_root_is_guarded(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('HOME / "repos" / "merges"', source)
        self.assertIn("immutable evidence", source)

    def test_synchronous_commands_have_bounded_runtime(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        assignments = {}
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                assignments[target.id] = node.value.value
        self.assertEqual(60, assignments.get("DEFAULT_TIMEOUT"))
        self.assertEqual(120, assignments.get("MAX_TIMEOUT"))

    def test_timeout_kills_the_full_process_group(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("start_new_session=True", source)
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", source)

    def test_http_transport_is_loopback_only(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('choices=("stdio", "streamable-http")', source)
        self.assertIn('args.host != "127.0.0.1"', source)
        self.assertIn('mcp.run(transport=args.transport)', source)


if __name__ == "__main__":
    unittest.main()
