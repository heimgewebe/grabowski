from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_agent_role as role
from grabowski_agent_sandbox import PreparedSandboxCommand


def stream_bytes(events: list[dict]) -> bytes:
    return ("\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n").encode()


def successful_git_tool_events(
    command: str = "git status --short --branch",
    *,
    call_id: str = "call-1",
) -> list[dict]:
    return [
        {
            "type": "tool_call",
            "toolCallId": call_id,
            "toolName": "run_terminal_command",
            "rawInput": {"command": command},
        },
        {
            "type": "tool_call_update",
            "toolCallId": call_id,
            "status": "completed",
            "rawOutput": {"exit_code": 0, "command": command},
        },
    ]


class GrokReviewRoleTests(unittest.TestCase):
    def test_streaming_review_command_enforces_git_only_read_contract(self) -> None:
        prepared = (
            "/opt/grabowski-external/grok",
            "--model",
            "grok-4.6",
            "-p",
            "review this",
        )

        actual = role._grok_streaming_review_command(prepared)

        self.assertEqual(actual[0:3], prepared[0:3])
        self.assertNotIn("--always-approve", actual)
        self.assertEqual(actual[actual.index("--sandbox") + 1], "read-only")
        self.assertEqual(actual[actual.index("--tools") + 1], "run_terminal_cmd")
        self.assertEqual(actual[actual.index("--output-format") + 1], "streaming-json")
        self.assertEqual(actual[actual.index("--max-turns") + 1], str(role.GROK_REVIEW_MAX_TURNS))
        allow_values = [actual[index + 1] for index, value in enumerate(actual) if value == "--allow"]
        deny_values = [actual[index + 1] for index, value in enumerate(actual) if value == "--deny"]
        self.assertEqual(tuple(allow_values), role.GROK_REVIEW_ALLOW_RULES)
        self.assertEqual(tuple(deny_values), role.GROK_REVIEW_DENY_RULES)
        self.assertIn("Bash(git diff --no-ext-diff --no-textconv*)", allow_values)
        self.assertIn("Bash(*;*)", deny_values)
        self.assertIn("Bash(*&*)", deny_values)
        self.assertIn("Bash(*.grok*)", deny_values)
        self.assertIn("Bash(*--ext-diff*)", deny_values)
        self.assertIn("Bash(*--textconv*)", deny_values)
        self.assertIn("Bash(*--no-index*)", deny_values)
        self.assertIn("Bash(*--output*)", deny_values)
        self.assertEqual(actual[-2], "-p")
        self.assertTrue(actual[-1].startswith("review this"))
        self.assertIn("Do not wrap", actual[-1])
        self.assertIn("git diff --no-ext-diff --no-textconv", actual[-1])

    def test_streaming_review_command_rejects_caller_owned_execution_framing(self) -> None:
        controlled = (
            "--always-approve",
            "--yolo",
            "--dangerously-skip-permissions",
            "--permission-mode",
            "--allow",
            "--deny",
            "--sandbox",
            "--tools",
            "--disallowed-tools",
            "--output-format",
            "--max-turns",
            "--json-schema",
        )
        for option in controlled:
            with self.subTest(option=option, form="separate"):
                prepared = (
                    "/opt/grabowski-external/grok",
                    option,
                    "value",
                    "-p",
                    "review this",
                )
                with self.assertRaisesRegex(RuntimeError, "controlled by Grabowski"):
                    role._grok_streaming_review_command(prepared)
            with self.subTest(option=option, form="attached"):
                prepared = (
                    "/opt/grabowski-external/grok",
                    f"{option}=value",
                    "-p",
                    "review this",
                )
                with self.assertRaisesRegex(RuntimeError, "controlled by Grabowski"):
                    role._grok_streaming_review_command(prepared)

    def test_review_sandbox_preserves_declared_command_for_provenance(self) -> None:
        repo = Path("/tmp/repo")
        declared = ["grok", "--model", "grok-4.6", "review this"]
        prepared = PreparedSandboxCommand(
            command=(
                "/opt/grabowski-external/grok",
                "--model",
                "grok-4.6",
                "-p",
                "review this",
            )
        )
        with (
            mock.patch.object(role, "prepare_external_agent_command", return_value=prepared),
            mock.patch.object(role, "sandbox_argv", return_value=["sandbox"]) as sandbox_argv,
        ):
            argv, contract = role._review_sandbox_argv(repo, declared)

        self.assertEqual(argv, ["sandbox"])
        self.assertEqual(contract, role.GROK_REVIEW_STREAM_CONTRACT)
        actual = sandbox_argv.call_args.args[1]
        self.assertIn("--output-format", actual)
        self.assertNotIn("--always-approve", actual)
        self.assertEqual(sandbox_argv.call_args.kwargs["declared_command"], declared)

    def test_safe_grok_git_read_command_accepts_only_bounded_read_forms(self) -> None:
        accepted = (
            "git status --short --branch",
            "git diff --no-ext-diff --no-textconv HEAD~1...HEAD -- src tests",
            "git cat-file blob HEAD:src/app.py",
            "git rev-parse HEAD",
            "git merge-base main HEAD",
            "git ls-files src tests",
        )
        rejected = (
            "git diff HEAD~1...HEAD",
            "git diff --no-ext-diff --no-textconv HEAD~1...HEAD --ext-diff",
            "git diff --no-ext-diff --no-textconv --textconv HEAD~1...HEAD",
            "git diff --no-ext-diff --no-textconv --no-index /etc/passwd /dev/null",
            "git diff --no-ext-diff --no-textconv HEAD~1...HEAD --output=/tmp/out",
            "git branch -D main",
            "git log --no-patch -5 --oneline",
            "git status --short --branch --ignored",
            "git status --short --branch; cat /tmp/.grok/auth.json",
            "git rev-parse HEAD & cat /tmp/.grok/auth.json",
            "git diff --no-ext-diff --no-textconv HEAD | cat",
            "git cat-file blob $(cat /tmp/.grok/auth.json)",
            "git ls-files .grok/auth.json",
            "git ls-files 'auth.json'",
            "git rev-parse HEAD:.grok/auth.json",
            "git log -p -1",
            "cat src/app.py",
            "git status\ncat /tmp/.grok/auth.json",
        )
        for command in accepted:
            with self.subTest(command=command):
                self.assertTrue(role._safe_grok_git_read_command(command))
        for command in rejected:
            with self.subTest(command=command):
                self.assertFalse(role._safe_grok_git_read_command(command))

    def test_terminal_json_object_accepts_unique_object_suffix_after_prose(self) -> None:
        review = role._terminal_json_object(
            "Reviewed the exact diff.\n\n{\n  \"verdict\": \"PASS\",\n  \"findings\": []\n}\n"
        )
        self.assertEqual(review, {"verdict": "PASS", "findings": []})
        self.assertIsNone(role._terminal_json_object("no final object"))
        self.assertIsNone(
            role._terminal_json_object(
                "```json\n{\"verdict\":\"PASS\",\"findings\":[]}\n```"
            )
        )

    def test_extract_stream_requires_successful_bounded_git_tool_and_terminal_review(self) -> None:
        command = "git diff --no-ext-diff --no-textconv HEAD~1...HEAD -- src tests"
        events = [
            {"type": "text", "data": "I will inspect."},
            *successful_git_tool_events(command),
            {"type": "text", "data": "Reviewed.\n\n"},
            {"type": "text", "data": '{"verdict":"PASS","findings":[]}'},
            {"type": "end", "stopReason": "end_turn", "num_turns": 2},
        ]

        document, error, metadata = role._extract_grok_stream_review_document(
            stream_bytes(events)
        )

        self.assertIsNone(error)
        self.assertEqual(json.loads(document), {"verdict": "PASS", "findings": []})
        self.assertEqual(metadata["review_provider_completed_tool_calls"], 1)
        self.assertEqual(metadata["review_provider_completed_tools"], ["run_terminal_command"])
        self.assertEqual(metadata["review_provider_completed_commands"], [command])
        self.assertEqual(metadata["review_provider_num_turns"], 2)

    def test_extract_stream_fails_closed_on_unsafe_or_failed_git_tool(self) -> None:
        cases = (
            (
                [
                    {
                        "type": "tool_call",
                        "toolCallId": "read-1",
                        "toolName": "read_file",
                        "rawInput": {"path": "src/app.py"},
                    },
                    {"type": "end", "stopReason": "end_turn", "num_turns": 2},
                ],
                "disallowed tool",
            ),
            (
                [
                    {
                        "type": "tool_call",
                        "toolCallId": "call-1",
                        "toolName": "run_terminal_command",
                        "rawInput": {"command": "git branch -D main"},
                    },
                    {"type": "end", "stopReason": "end_turn", "num_turns": 2},
                ],
                "non-read-only Git command",
            ),
            (
                [
                    {
                        "type": "tool_call",
                        "toolCallId": "call-1",
                        "toolName": "run_terminal_command",
                        "rawInput": {"command": "git status --short --branch"},
                    },
                    {
                        "type": "tool_call_update",
                        "toolCallId": "call-1",
                        "status": "completed",
                        "rawOutput": {"exit_code": 1, "command": "git status --short --branch"},
                    },
                    {"type": "end", "stopReason": "end_turn", "num_turns": 2},
                ],
                "did not succeed",
            ),
            (
                [
                    {
                        "type": "tool_call",
                        "toolCallId": "call-1",
                        "toolName": "run_terminal_command",
                        "rawInput": {"command": "git status --short --branch"},
                    },
                    {
                        "type": "tool_call_update",
                        "toolCallId": "call-1",
                        "status": "completed",
                        "rawOutput": {"exit_code": 0, "command": "git rev-parse HEAD"},
                    },
                    {"type": "end", "stopReason": "end_turn", "num_turns": 2},
                ],
                "changed between request",
            ),
        )
        for events, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                document, error, _metadata = role._extract_grok_stream_review_document(
                    stream_bytes(events)
                )
                self.assertIsNone(document)
                self.assertIn(expected_error, error)

    def test_extract_stream_fails_closed_without_complete_tool_review(self) -> None:
        base_tool = successful_git_tool_events()
        cases = (
            (
                [
                    {"type": "text", "data": '{"verdict":"PASS","findings":[]}'},
                    {"type": "end", "stopReason": "end_turn", "num_turns": 1},
                ],
                "completed no read-only",
            ),
            (
                [
                    base_tool[0],
                    {
                        "type": "tool_call_update",
                        "toolCallId": "call-1",
                        "status": "failed",
                    },
                    {"type": "end", "stopReason": "end_turn", "num_turns": 2},
                ],
                "did not complete",
            ),
            (
                [
                    *base_tool,
                    {
                        "type": "tool_call",
                        "toolCallId": "call-2",
                        "toolName": "run_terminal_command",
                        "rawInput": {"command": "git rev-parse HEAD"},
                    },
                    {"type": "text", "data": '{"verdict":"PASS","findings":[]}'},
                    {"type": "end", "stopReason": "end_turn", "num_turns": 3},
                ],
                "left a repository tool call incomplete",
            ),
            (
                [
                    base_tool[0],
                    base_tool[0],
                    base_tool[1],
                    {"type": "text", "data": '{"verdict":"PASS","findings":[]}'},
                    {"type": "end", "stopReason": "end_turn", "num_turns": 2},
                ],
                "reused a tool call identity",
            ),
            (
                [
                    *base_tool,
                    base_tool[1],
                    {"type": "text", "data": '{"verdict":"PASS","findings":[]}'},
                    {"type": "end", "stopReason": "end_turn", "num_turns": 2},
                ],
                "completed a tool call more than once",
            ),
            (
                [
                    *base_tool,
                    {"type": "text", "data": '{"verdict":"PASS","findings":[]}'},
                    {"type": "end", "stopReason": "cancelled", "num_turns": 2},
                ],
                "end_turn",
            ),
            (
                [
                    *base_tool,
                    {"type": "text", "data": "```json\n{\"verdict\":\"PASS\",\"findings\":[]}\n```"},
                    {"type": "end", "stopReason": "end_turn", "num_turns": 2},
                ],
                "unique JSON object suffix",
            ),
        )
        for events, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                document, error, _metadata = role._extract_grok_stream_review_document(
                    stream_bytes(events)
                )
                self.assertIsNone(document)
                self.assertIn(expected_error, error)


if __name__ == "__main__":
    unittest.main()
