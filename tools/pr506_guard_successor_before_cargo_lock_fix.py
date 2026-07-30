#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import textwrap


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "grabowski_tasks.py"
TESTS = ROOT / "tests" / "test_tasks.py"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label} anchor count is {count}, expected 1")
    return text.replace(old, new, 1)


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    tests = TESTS.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''def _terminal_retry_successor(
    record: dict[str, Any],
    *,
    reason: str,
    explicit_policy_override: bool = False,
) -> dict[str, Any]:
    context = (
''',
        '''def _terminal_retry_successor(
    record: dict[str, Any],
    *,
    reason: str,
    explicit_policy_override: bool = False,
) -> dict[str, Any]:
    _guard_linked_retry_successor(
        None,
        source_task_id=str(record["task_id"]),
    )
    context = (
''',
        "terminal retry successor preflight",
    )

    method = textwrap.indent(
        textwrap.dedent(
            '''
            def test_retained_cargo_successor_blocks_before_lock_preparation(self) -> None:
                raw_command = ["/usr/bin/cargo", "test"]
                cache_key = "d" * 64
                target = tasks.MANAGED_CARGO_CACHE_ROOT / cache_key / "target"
                lock = tasks.MANAGED_CARGO_LOCK_ROOT / f"{cache_key}.lock"
                bound = [
                    tasks.FLOCK_EXECUTABLE,
                    "--shared",
                    str(lock),
                    tasks.SYSTEMD_ENV_EXECUTABLE,
                    f"CARGO_TARGET_DIR={target}",
                    *raw_command,
                ]
                with (
                    patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                    patch.object(
                        tasks,
                        "_managed_cargo_request_root",
                        return_value=self.root,
                    ),
                    patch.object(
                        tasks,
                        "_bind_managed_cargo_environment",
                        return_value=bound,
                    ),
                    patch.object(tasks, "_dispatch", return_value=_launcher()),
                    patch.object(tasks.base, "_append_audit"),
                    patch.object(
                        tasks,
                        "_require_recovery_gate",
                        return_value={"checked_at_unix": 190},
                    ),
                ):
                    source = tasks.grabowski_task_start(
                        "local",
                        raw_command,
                        cwd=str(self.root),
                        runtime_seconds=60,
                        resume_policy="manual",
                        cpu_weight=50,
                        io_weight=25,
                    )["task"]
                source_id = str(source["task_id"])
                tasks._set_state(
                    source_id,
                    "failed",
                    observation={"state": "failed", "source": "test"},
                )

                with (
                    patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                    patch.object(
                        tasks,
                        "_managed_cargo_lifecycle_lock",
                        return_value=lock,
                    ),
                    patch.object(tasks, "_dispatch", return_value=_launcher()),
                    patch.object(tasks.base, "_append_audit"),
                    patch.object(
                        tasks,
                        "_require_recovery_gate",
                        return_value={"checked_at_unix": 191},
                    ),
                ):
                    first = tasks.reconcile_tasks_resume(
                        task_id=source_id,
                        reason="operator repaired the Cargo failure",
                        max_resumes=1,
                    )
                self.assertEqual([], first["blocked"])
                self.assertEqual(1, len(first["resumed"]))
                successor_id = str(first["resumed"][0]["task_id"])
                retained = tasks._retained_retry_successor_for_source(source_id)
                self.assertIsNotNone(retained)
                self.assertEqual(successor_id, retained["task_id"])

                with (
                    patch.object(tasks, "_managed_cargo_lifecycle_lock") as prepare_lock,
                    patch.object(tasks, "grabowski_task_start") as start,
                ):
                    duplicate = tasks.reconcile_tasks_resume(
                        task_id=source_id,
                        reason="attempted duplicate Cargo successor",
                        max_resumes=1,
                    )
                self.assertEqual([], duplicate["resumed"])
                self.assertEqual(1, len(duplicate["blocked"]))
                self.assertIn("retry successor", duplicate["blocked"][0]["reason"])
                prepare_lock.assert_not_called()
                start.assert_not_called()

            '''
        ),
        "    ",
    )
    anchor = "    def test_terminal_retry_replays_managed_cargo_binding_once(self) -> None:\n"
    if "def test_retained_cargo_successor_blocks_before_lock_preparation" not in tests:
        if tests.count(anchor) != 1:
            raise RuntimeError("Cargo retry test anchor is ambiguous")
        tests = tests.replace(anchor, method + anchor, 1)

    SOURCE.write_text(source, encoding="utf-8")
    TESTS.write_text(tests, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
