from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).parents[1]
OBSERVER_PATH = ROOT / "tools/grabowski_safety_observer.py"


def load_observer(tmp_path: Path):
    spec = importlib.util.spec_from_file_location("grabowski_safety_observer_test", OBSERVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state = tmp_path / "state"
    module.STATE_DIR = state
    module.EVENTS_PATH = state / "events.jsonl"
    module.SNAPSHOTS_PATH = state / "snapshots.jsonl"
    module.CURSOR_PATH = state / "cursor.json"
    module.DEDUP_PATH = state / "dedup.json"
    module.STATUS_PATH = state / "status.json"
    module.REPORT_PATH = state / "report.md"
    module.LOCK_PATH = state / "observer.lock"
    return module


def test_redact_removes_secret_like_values(tmp_path: Path):
    observer = load_observer(tmp_path)

    fake_secret = "sk-" + "testsecret123456789"
    text = observer.redact(f"Authorization: Bearer abc.def API_KEY={fake_secret}")

    assert fake_secret not in text
    assert "Bearer abc" not in text
    assert "<REDACTED>" in text


def test_record_event_deduplicates_and_stores_no_raw_secret(tmp_path: Path):
    observer = load_observer(tmp_path)

    fake_secret = "sk-" + "abcdefghijklmnopqrstuvwxyz"

    first = observer.record_event(
        kind="upstream_policy_block",
        source="tool-call",
        tool="grabowski_terminal_run",
        operation_class="write",
        message=f"token={fake_secret} blocked",
        deduplicate=True,
    )
    second = observer.record_event(
        kind="upstream_policy_block",
        source="tool-call",
        tool="grabowski_terminal_run",
        operation_class="write",
        message=f"token={fake_secret} blocked",
        deduplicate=True,
    )

    assert first is not None
    assert second is None
    stored = observer.EVENTS_PATH.read_text(encoding="utf-8")
    assert fake_secret not in stored
    assert "<REDACTED>" in stored


def test_build_status_marks_repeated_policy_blocks_amber(tmp_path: Path):
    observer = load_observer(tmp_path)

    for index in range(3):
        observer.record_event(
            kind="upstream_policy_block",
            source=f"source-{index}",
            tool="grabowski_terminal_run",
            operation_class="read",
            message=f"blocked {index}",
        )

    status = observer.build_status()

    assert status["risk"] == "amber"
    assert status["counts_24h"]["upstream_policy_block"] == 3
    assert status["policy"]["automatic_retry_after_upstream_block"] is False
    assert status["policy"]["alter_platform_safeguards"] is False


def test_report_excludes_expected_restart_as_actionable(tmp_path: Path):
    observer = load_observer(tmp_path)
    observer.record_event(
        kind="expected_service_restart",
        source="systemd",
        tool="grabowski-operator.service",
        operation_class="read",
        message="received signal terminated",
    )

    status = observer.build_status()
    report = observer.render_report(status)

    assert status["risk"] == "green"
    assert "Suppressed non-actionable" in report
    assert "expected_service_restart" not in status["counts_24h"]
