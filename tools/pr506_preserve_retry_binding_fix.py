#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import textwrap


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "grabowski_tasks.py"
TESTS = ROOT / "tests" / "test_tasks.py"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(f"{label} anchor count is {text.count(old)}, expected 1")
    return text.replace(old, new, 1)


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    tests = TESTS.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''    interrupted_recovery_binding = None
    if _interrupted_recovery_context is not None:
        interrupted_recovery_binding = _validate_interrupted_recovery_context(
            _interrupted_recovery_context,
            record=record,
            observation=observation,
        )
''',
        '''    interrupted_recovery_binding = None
    recovery_launcher_bindings: dict[str, Any] = {}
    if _interrupted_recovery_context is not None:
        interrupted_recovery_binding = _validate_interrupted_recovery_context(
            _interrupted_recovery_context,
            record=record,
            observation=observation,
        )
        recovery_launcher_bindings["interrupted_recovery_binding"] = (
            interrupted_recovery_binding
        )
        retained_retry_binding = _persisted_retry_binding_or_raise(record)
        if retained_retry_binding is not None:
            recovery_launcher_bindings["retry_binding"] = retained_retry_binding
''',
        "interrupted recovery validation",
    )
    source = replace_once(
        source,
        '''            launcher={
                "pending": True,
                "interrupted_recovery_binding": interrupted_recovery_binding,
            },
''',
        '''            launcher={
                "pending": True,
                **recovery_launcher_bindings,
            },
''',
        "pending recovery launcher",
    )
    source = replace_once(
        source,
        '''    if interrupted_recovery_binding is not None:
        launcher = {
            **launcher,
            "interrupted_recovery_binding": interrupted_recovery_binding,
        }
''',
        '''    if interrupted_recovery_binding is not None:
        launcher = {
            **launcher,
            **recovery_launcher_bindings,
        }
''',
        "post-launch recovery bindings",
    )

    test_methods = textwrap.indent(
        textwrap.dedent(
            '''
            def test_interrupted_retry_successor_recovery_preserves_retry_binding(self) -> None:
                started = self._start()
                source = tasks._set_state(
                    str(started["task"]["task_id"]),
                    "failed",
                    observation={"state": "failed", "source": "test"},
                )
                with (
                    patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                    patch.object(tasks, "_dispatch", return_value=_launcher()),
                    patch.object(tasks.base, "_append_audit"),
                    patch.object(
                        tasks,
                        "_require_recovery_gate",
                        return_value={"checked_at_unix": 180},
                    ),
                ):
                    first_retry = tasks.reconcile_tasks_resume(
                        task_id=str(source["task_id"]),
                        reason="operator repaired the original failure",
                        max_resumes=1,
                    )
                self.assertEqual([], first_retry["blocked"])
                successor_id = str(first_retry["resumed"][0]["task_id"])
                successor = tasks._row_raw(successor_id)
                retry_binding = tasks._persisted_retry_binding_or_raise(successor)
                self.assertIsNotNone(retry_binding)

                tasks._set_state(
                    successor_id,
                    "interrupted",
                    observation={"state": "interrupted", "source": "host-restart"},
                )
                admitted = _missing_unit_observation(
                    observed_at_unix=181,
                    duration_seconds=0.01,
                )
                revalidated = _missing_unit_observation(
                    observed_at_unix=182,
                    duration_seconds=0.02,
                )
                observed_launchers: list[dict[str, object]] = []

                def launch_with_retry_edge(record: dict[str, object]) -> dict[str, object]:
                    pending = tasks._row_raw(successor_id)
                    launcher = json.loads(str(pending["launcher_json"]))
                    self.assertEqual("launching", pending["state"])
                    self.assertEqual(retry_binding, launcher["retry_binding"])
                    self.assertIn("interrupted_recovery_binding", launcher)
                    observed_launchers.append(launcher)
                    return _launcher()

                with (
                    patch.object(tasks, "_reconcile_observation", return_value=admitted),
                    patch.object(tasks, "_observe", return_value=revalidated),
                    patch.object(tasks, "_launch", side_effect=launch_with_retry_edge),
                    patch.object(tasks.base, "_append_audit"),
                    patch.object(
                        tasks,
                        "_require_recovery_gate",
                        return_value={"checked_at_unix": 182},
                    ),
                ):
                    recovered = tasks.reconcile_tasks_resume(
                        task_id=successor_id,
                        reason="operator repaired the interrupted successor",
                        max_resumes=1,
                    )

                self.assertEqual([], recovered["blocked"])
                self.assertEqual(1, len(recovered["resumed"]))
                self.assertEqual(1, len(observed_launchers))
                persisted = tasks._row_raw(successor_id)
                persisted_launcher = json.loads(str(persisted["launcher_json"]))
                self.assertEqual(retry_binding, persisted_launcher["retry_binding"])
                self.assertIn("interrupted_recovery_binding", persisted_launcher)
                self.assertEqual(
                    retry_binding,
                    tasks._persisted_retry_binding_or_raise(persisted),
                )
                retained = tasks._retained_retry_successor_for_source(
                    str(source["task_id"])
                )
                self.assertIsNotNone(retained)
                self.assertEqual(successor_id, retained["task_id"])

                with (
                    patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                    patch.object(tasks, "_dispatch", return_value=_launcher()),
                    patch.object(tasks.base, "_append_audit"),
                    patch.object(
                        tasks,
                        "_require_recovery_gate",
                        return_value={"checked_at_unix": 183},
                    ),
                ):
                    duplicate = tasks.reconcile_tasks_resume(
                        task_id=str(source["task_id"]),
                        reason="attempted duplicate successor",
                        max_resumes=1,
                    )
                self.assertEqual([], duplicate["resumed"])
                self.assertIn("retry successor", duplicate["blocked"][0]["reason"])

            def test_interrupted_recovery_rejects_malformed_retry_binding_before_effects(
                self,
            ) -> None:
                resource_key = f"path:{self.root}"
                started = self._start(resource_keys=[resource_key])
                task_id = str(started["task"]["task_id"])
                tasks._set_state(
                    task_id,
                    "interrupted",
                    observation={"state": "interrupted", "source": "host-restart"},
                )
                with tasks._database() as connection:
                    connection.execute(
                        "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                        (json.dumps({"retry_binding": {"source_task_id": "bad"}}), task_id),
                    )
                    connection.commit()
                admitted = _missing_unit_observation(
                    observed_at_unix=184,
                    duration_seconds=0.01,
                )
                revalidated = _missing_unit_observation(
                    observed_at_unix=185,
                    duration_seconds=0.02,
                )
                with (
                    patch.object(tasks, "_reconcile_observation", return_value=admitted),
                    patch.object(tasks, "_observe", return_value=revalidated),
                    patch.object(tasks.resources, "acquire_resources") as acquire,
                    patch.object(tasks, "_launch") as launch,
                    patch.object(
                        tasks,
                        "_require_recovery_gate",
                        return_value={"checked_at_unix": 185},
                    ),
                ):
                    result = tasks.reconcile_tasks_resume(
                        task_id=task_id,
                        reason="operator repaired the interrupted task",
                        max_resumes=1,
                    )
                self.assertEqual([], result["resumed"])
                self.assertIn(
                    "stored retry admission evidence is invalid",
                    result["blocked"][0]["reason"],
                )
                acquire.assert_not_called()
                launch.assert_not_called()
                persisted = tasks._row_raw(task_id)
                self.assertEqual("interrupted", persisted["state"])
                self.assertEqual(1, persisted["attempt"])

            '''
        ),
        "    ",
    )
    anchor = "    def test_interrupted_recovery_requires_exact_task_target(self) -> None:\n"
    if "def test_interrupted_retry_successor_recovery_preserves_retry_binding" not in tests:
        if tests.count(anchor) != 1:
            raise RuntimeError("interrupted recovery test anchor is ambiguous")
        tests = tests.replace(anchor, test_methods + anchor, 1)

    SOURCE.write_text(source, encoding="utf-8")
    TESTS.write_text(tests, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
