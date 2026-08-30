from __future__ import annotations

import json
from pathlib import Path

from experimental.trajectory_shadow import trajectory_shadow as ts


def event(sequence: int, *, operation: str = "execute", outcome: str = "success", action: str | None = None, result: str | None = None, target: str | None = None, state_epoch: int = 0, mutation_from: str | None = None, mutation_to: str | None = None) -> ts.Event:
    return ts.Event(sequence=sequence, timestamp=float(sequence), actor="writer", operation=operation, target_kind="file" if target else None, target=target, outcome=outcome, action_fingerprint=action or f"action-{sequence}", result_fingerprint=result, source_adapter="test", evidence_ref=f"test#{sequence}", state_epoch=state_epoch, mutation_from=mutation_from, mutation_to=mutation_to)


def detector_names(events: list[ts.Event], *, terminal: bool = False) -> list[str]:
    return [item["detector"] for item in ts.detect(events, terminal_evidenced=terminal)]


def test_repeated_failure_requires_same_failure_and_no_state_or_evidence_delta() -> None:
    repeated = [event(1, outcome="failure", action="same", result="same-result", state_epoch=0), event(2, outcome="failure", action="same", result="same-result", state_epoch=0)]
    assert "repeated_failure_without_state_delta" in detector_names(repeated)
    after_state_change = [event(1, outcome="failure", action="same", result="same-result", state_epoch=0), event(2, operation="edit", target="src/a.py", state_epoch=0), event(3, outcome="failure", action="same", result="same-result", state_epoch=1)]
    assert "repeated_failure_without_state_delta" not in detector_names(after_state_change)
    after_new_evidence = [event(1, outcome="failure", action="same", result="same-result", state_epoch=0), event(2, operation="read", target="src/a.py", result="read-result", state_epoch=0), event(3, outcome="failure", action="same", result="same-result", state_epoch=0)]
    assert "repeated_failure_without_state_delta" not in detector_names(after_new_evidence)


def test_verification_gap_requires_closeout_and_post_verification_mutation() -> None:
    events = [event(1, operation="verify", result="tests-pass", state_epoch=0), event(2, operation="edit", target="src/a.py", state_epoch=0)]
    assert "verification_gap" not in detector_names(events, terminal=False)
    assert "verification_gap" in detector_names(events, terminal=True)
    verified_after_change = [event(1, operation="edit", target="src/a.py", state_epoch=0), event(2, operation="verify", result="tests-pass", state_epoch=1)]
    assert "verification_gap" not in detector_names(verified_after_change, terminal=True)


def test_mutation_localization_accepts_read_search_and_context() -> None:
    findings = ts.detect([event(1, operation="edit", target="src/a.py")], terminal_evidenced=False)
    localization = [item for item in findings if item["detector"] == "mutation_without_evidenced_localization"]
    assert len(localization) == 1
    assert localization[0]["confidence"] == 0.55
    assert localization[0]["task_supplied_evidence_unobservable"] is True
    direct_read = [event(1, operation="read", target="src/a.py", result="r"), event(2, operation="edit", target="src/a.py")]
    assert "mutation_without_evidenced_localization" not in detector_names(direct_read)
    parent_search = [event(1, operation="search", target="src", result="r"), event(2, operation="edit", target="src/a.py")]
    assert "mutation_without_evidenced_localization" not in detector_names(parent_search)
    repoground_context = [event(1, operation="context", target=".", result="ctx"), event(2, operation="edit", target="src/a.py")]
    assert "mutation_without_evidenced_localization" not in detector_names(repoground_context)


def test_abab_oscillation_requires_same_results_and_no_state_delta() -> None:
    oscillation = [event(1, action="A", result="ra", state_epoch=0), event(2, action="B", result="rb", state_epoch=0), event(3, action="A", result="ra", state_epoch=0), event(4, action="B", result="rb", state_epoch=0)]
    findings = ts.detect(oscillation, terminal_evidenced=False)
    assert any(item["detector"] == "action_oscillation_without_progress" and item["pattern"] == "ABAB_same_results_no_state_delta" for item in findings)
    progress = [event(1, action="A", result="ra", state_epoch=0), event(2, action="B", result="rb", state_epoch=0), event(3, action="A", result="ra", state_epoch=1), event(4, action="B", result="rb", state_epoch=1)]
    assert "action_oscillation_without_progress" not in detector_names(progress)


def test_edit_fail_undo_same_edit_same_fail_is_detected() -> None:
    events = [event(1, operation="edit", target="src/a.py", mutation_from="old", mutation_to="new", state_epoch=0), event(2, operation="verify", outcome="failure", action="tests", result="failure", state_epoch=1), event(3, operation="edit", target="src/a.py", mutation_from="new", mutation_to="old", state_epoch=1), event(4, operation="edit", target="src/a.py", mutation_from="old", mutation_to="new", state_epoch=2), event(5, operation="verify", outcome="failure", action="tests", result="failure", state_epoch=3)]
    findings = ts.detect(events, terminal_evidenced=False)
    assert any(item["detector"] == "action_oscillation_without_progress" and item["pattern"] == "edit_fail_undo_same_edit_same_fail" for item in findings)


def test_exact_attribution_rejects_target_only_and_ambiguous_targets(tmp_path: Path) -> None:
    session = ts.Session(adapter="codex", path=tmp_path / "session.jsonl", session_id="s1", cwd="/tmp/worktree", branch="branch-a", base_commit="base-a", tool_actions=4, first_at=1.0, last_at=2.0)
    lane = ts.Lane(lane_id="lane-1", target_path="/tmp/worktree", branch="branch-a", base_head="base-a", repo="/tmp/repo", source_kind="prompt", source_id=None, state="ready", created_at=1.0, updated_at=2.0, closeout_state=None, baseline_observed_at=None, baseline_reason_codes=())
    matches = ts.exact_attributions([lane], [session])
    assert matches["lane-1"][1][0][1] == ("branch", "base_revision")
    conflicting_base = ts.Session(adapter="codex", path=tmp_path / "conflict.jsonl", session_id="conflict", cwd="/tmp/worktree", branch="branch-a", base_commit="different-base", tool_actions=1, first_at=1.0, last_at=2.0)
    assert ts.exact_attributions([lane], [conflicting_base]) == {}
    target_only = ts.Session(adapter="claude", path=tmp_path / "session2.jsonl", session_id="s2", cwd="/tmp/worktree", branch=None, base_commit=None, tool_actions=10, first_at=1.0, last_at=2.0)
    assert ts.exact_attributions([lane], [target_only]) == {}
    duplicate = ts.Lane(lane_id="lane-2", target_path="/tmp/worktree", branch="branch-a", base_head="base-a", repo="/tmp/repo", source_kind="prompt", source_id=None, state="ready", created_at=1.0, updated_at=2.0, closeout_state=None, baseline_observed_at=None, baseline_reason_codes=())
    assert ts.exact_attributions([lane, duplicate], [session]) == {}

    second_exact = ts.Session(adapter="claude", path=tmp_path / "session3.jsonl", session_id="s3", cwd="/tmp/worktree", branch="branch-a", base_commit=None, tool_actions=2, first_at=3.0, last_at=4.0)
    grouped = ts.exact_attributions([lane], [session, second_exact])
    assert len(grouped["lane-1"][1]) == 2


def test_claude_external_write_is_not_a_repo_mutation() -> None:
    tool = {"name": "Write", "input": {"file_path": "/home/alex/.claude/plans/example.md", "content": "not persisted"}}
    e = ts._event_from_claude_tool(1, 1.0, tool, "/home/alex/repos/worktree", "session")
    assert e.operation == "execute"
    assert e.target is None
    assert e.mutation_from is None
    assert e.mutation_to is None


def test_sanitized_event_contains_digests_but_no_raw_content() -> None:
    secret = "do-not-persist-this-raw-text"
    digest = ts._result_fingerprint({"stdout": secret})
    payload = event(1, operation="read", target="src/a.py", result=digest).sanitized()
    serialized = str(payload)
    assert secret not in serialized
    assert digest in serialized
    assert "command" not in payload
    assert "prompt" not in payload


def test_promotion_candidates_exclude_localization_only(tmp_path: Path) -> None:
    lane = ts.Lane(lane_id="lane-1", target_path="/tmp/worktree", branch="branch-a", base_head="base-a", repo="/tmp/repo", source_kind="prompt", source_id=None, state="ready", created_at=1.0, updated_at=10.0, closeout_state="pr_merged", baseline_observed_at=10.0, baseline_reason_codes=("merged_pr_observed",))
    session = ts.Session(adapter="claude", path=tmp_path / "session.jsonl", session_id="s1", cwd="/tmp/worktree", branch="branch-a", base_commit=None, tool_actions=3, first_at=1.0, last_at=3.0)
    events = [event(1, operation="edit", target="src/a.py"), event(2, operation="read", target="src/b.py", result="r"), event(3, operation="execute", result="x")]
    result = ts.evaluate_lane(lane, session, events, ("branch",))
    assert result["finding_counts"]["mutation_without_evidenced_localization"] == 1
    assert all(item["detector"] != "mutation_without_evidenced_localization" for item in result["promotion_candidates"])


def test_blocked_closeout_does_not_create_verification_gap() -> None:
    lane = ts.Lane(lane_id="blocked", target_path="/tmp/worktree", branch="branch", base_head="base", repo="/tmp/repo", source_kind="prompt", source_id=None, state="blocked", created_at=1.0, updated_at=3.0, closeout_state="blocked_with_durable_followup", baseline_observed_at=3.0, baseline_reason_codes=("failure_observed",))
    session = ts.Session(adapter="claude", path=Path("/tmp/session"), session_id="s", cwd="/tmp/worktree", branch="branch", base_commit=None, tool_actions=1, first_at=1.0, last_at=2.0)
    result = ts.evaluate_lane(lane, session, [event(1, operation="edit", target="src/a.py", outcome="success")], ("branch",))
    assert result["finding_counts"].get("verification_gap", 0) == 0


def test_edit_fail_undo_pattern_requires_successful_edits() -> None:
    events = [event(1, operation="edit", target="src/a.py", outcome="failure", mutation_from="old", mutation_to="new", state_epoch=0), event(2, operation="verify", outcome="failure", action="tests", result="failure", state_epoch=0), event(3, operation="edit", target="src/a.py", outcome="success", mutation_from="new", mutation_to="old", state_epoch=0), event(4, operation="edit", target="src/a.py", outcome="success", mutation_from="old", mutation_to="new", state_epoch=1), event(5, operation="verify", outcome="failure", action="tests", result="failure", state_epoch=2)]
    findings = ts.detect(events, terminal_evidenced=False)
    assert not any(item["detector"] == "action_oscillation_without_progress" and item.get("pattern") == "edit_fail_undo_same_edit_same_fail" for item in findings)


def test_codex_command_schemas_and_explicit_outcomes(tmp_path: Path) -> None:
    session_path = tmp_path / "codex.jsonl"
    rows = [
        {"type": "response_item", "timestamp": "2026-08-29T00:00:01Z", "payload": {"type": "function_call", "name": "exec_command", "call_id": "c1", "arguments": json.dumps({"cmd": "pytest -q tests/test_example.py", "workdir": "/tmp/worktree"})}},
        {"type": "response_item", "timestamp": "2026-08-29T00:00:02Z", "payload": {"type": "function_call_output", "call_id": "c1", "output": "Chunk ID: a\nProcess exited with code 1\nFinal output:\nfailed"}},
        {"type": "response_item", "timestamp": "2026-08-29T00:00:03Z", "payload": {"type": "function_call", "name": "exec_command", "call_id": "c2", "arguments": json.dumps({"cmd": "cat README.md", "workdir": "/tmp/worktree"})}},
        {"type": "response_item", "timestamp": "2026-08-29T00:00:04Z", "payload": {"type": "function_call_output", "call_id": "c2", "output": "Chunk ID: b\nProcess exited with code 0\nFinal output:\nok"}},
        {"type": "response_item", "timestamp": "2026-08-29T00:00:05Z", "payload": {"type": "function_call", "name": "shell", "call_id": "c3", "arguments": json.dumps({"command": ["bash", "-lc", "rg needle src"], "workdir": "/tmp/worktree"})}},
        {"type": "response_item", "timestamp": "2026-08-29T00:00:06Z", "payload": {"type": "function_call_output", "call_id": "c3", "output": "opaque shell output"}},
        {"type": "response_item", "timestamp": "2026-08-29T00:00:07Z", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c4", "input": "rg needle src"}},
        {"type": "response_item", "timestamp": "2026-08-29T00:00:08Z", "payload": {"type": "custom_tool_call_output", "call_id": "c4", "output": ["opaque", "output"]}},
        {"type": "response_item", "timestamp": "2026-08-29T00:00:09Z", "payload": {"type": "function_call", "name": "exec_command", "call_id": "c5", "arguments": json.dumps({"cmd": "cat AGENTS.md", "workdir": "/tmp/worktree"})}},
        {"type": "response_item", "timestamp": "2026-08-29T00:00:10Z", "payload": {"type": "function_call_output", "call_id": "c5", "output": "exit code: 1"}},
    ]
    session_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    session = ts.Session(adapter="codex", path=session_path, session_id="codex", cwd="/tmp/worktree", branch="branch", base_commit="base", tool_actions=5, first_at=1.0, last_at=10.0)
    events = ts.extract_codex(session)

    assert [item.operation for item in events] == ["verify", "read", "search", "search", "read"]
    assert [item.outcome for item in events] == ["failure", "success", "unknown", "unknown", "unknown"]
    assert events[0].result_fingerprint is not None
    assert events[1].result_fingerprint is not None
    assert events[4].confidence <= 0.75


def test_shell_verification_classification_is_structural() -> None:
    verification_commands = [
        "pytest -q tests/test_example.py",
        "python3 -m pytest -q",
        "cd /tmp && pytest -q",
        "timeout 120 pytest -q",
        "env FOO=bar ruff check .",
        "bash -lc 'python -m unittest tests.test_example'",
        "uv run pytest -q",
        "cargo test",
        "go test ./...",
        "npm run test",
        "make validate",
    ]
    for command in verification_commands:
        assert ts._classify_shell(command, "/tmp/worktree")[0] == "verify", command

    unsafe_verification_commands = [
        "true || pytest -q",
        "pytest -q || true",
        "pytest -q ; true",
        "pytest -q | cat",
        "bash -lc 'true || pytest -q'",
        "bash -lc 'pytest -q || true'",
        "bash -lc 'pytest -q | cat'",
    ]
    for command in unsafe_verification_commands:
        assert ts._classify_shell(command, "/tmp/worktree")[0] == "execute", command

    assert ts._classify_shell("cd /tmp ; pytest -q", "/tmp/worktree")[0] == "verify"
    assert ts._classify_shell("pytest -q && true", "/tmp/worktree")[0] == "verify"
    assert ts._classify_shell("bash -lc 'cd /tmp ; pytest -q'", "/tmp/worktree")[0] == "verify"
    assert ts._classify_shell("bash -lc 'pytest -q && true'", "/tmp/worktree")[0] == "verify"
    assert ts._classify_shell("rg pytest src", "/tmp/worktree")[0] == "search"
    assert ts._classify_shell("cat pytest.ini", "/tmp/worktree")[0] == "read"
    assert ts._classify_shell("printf pytest", "/tmp/worktree")[0] == "execute"
    assert ts._classify_shell('const x = "pytest"', "/tmp/worktree")[0] == "execute"
