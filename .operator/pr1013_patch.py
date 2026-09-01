from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one preimage, found {count}")
    return text.replace(old, new, 1)


tasks_path = Path("src/grabowski_tasks.py")
tasks = tasks_path.read_text()

tasks = replace_once(
    tasks,
    '''    executor_prelaunch_recovery: dict[str, Any] | None = None
    if executor_request is not None:
        if executor_lease_binding_request is None:
            raise RuntimeError(
                "Bureau runtime-refresh executor lost validated prelaunch authority"
            )
        executor_prelaunch_recovery = (
            _reconcile_runtime_refresh_prelaunch_binding_journals(
                executor_lease_binding_request["resource_keys"]
            )
        )
''',
    '''    executor_prelaunch_recovery: dict[str, Any] | None = None
    if executor_request is not None:
        if (
            executor_lease_binding_request is None
            or executor_intent is None
            or executor_authority_contract is None
        ):
            raise RuntimeError(
                "Bureau runtime-refresh executor lost validated prelaunch authority"
            )
        recovery_executor_intent = (
            bureau_runtime_refresh_executor.load_bound_intent(executor_request)
        )
        recovery_executor_authority_contract = (
            bureau_runtime_refresh_executor.validate_authority_execution_contract(
                recovery_executor_intent
            )
        )
        recovery_executor_lease_binding_request = (
            _runtime_refresh_prelaunch_lease_binding_request(
                executor_request,
                recovery_executor_intent,
                recovery_executor_authority_contract,
                task_id,
                _task_unit(task_id, 1),
            )
        )
        if recovery_executor_lease_binding_request != executor_lease_binding_request:
            raise RuntimeError(
                "Bureau runtime-refresh prelaunch authority changed before journal recovery"
            )
        executor_intent = recovery_executor_intent
        executor_authority_contract = recovery_executor_authority_contract
        executor_lease_binding_request = recovery_executor_lease_binding_request
        executor_prelaunch_recovery = (
            _reconcile_runtime_refresh_prelaunch_binding_journals(
                executor_lease_binding_request["resource_keys"]
            )
        )
''',
    "pre-recovery authority revalidation",
)

tasks = replace_once(
    tasks,
    '''            task_row = connection.execute(
                "SELECT task_id, unit, argv_sha256 FROM tasks WHERE task_id=?",
                (journal["task_id"],),
            ).fetchone()
            if task_row is not None:
                if (
                    task_row["task_id"] != journal["task_id"]
                    or task_row["unit"] != journal["executor_unit"]
                    or task_row["argv_sha256"] != journal["argv_sha256"]
                ):
                    raise RuntimeError(
                        "runtime-refresh prelaunch recovery task identity mismatched"
                    )
                _delete_runtime_refresh_prelaunch_binding_journal(
                    connection, journal
                )
                retained.append(journal["task_id"])
                continue
            recovery = resources.restore_runtime_refresh_executor_lease_binding_plan(
                journal["binding_plan"]
            )
''',
    '''            task_row = connection.execute(
                "SELECT task_id, unit, argv_sha256, launcher_json FROM tasks WHERE task_id=?",
                (journal["task_id"],),
            ).fetchone()
            if task_row is not None:
                if (
                    task_row["task_id"] != journal["task_id"]
                    or task_row["unit"] != journal["executor_unit"]
                    or task_row["argv_sha256"] != journal["argv_sha256"]
                ):
                    raise RuntimeError(
                        "runtime-refresh prelaunch recovery task identity mismatched"
                    )
                try:
                    task_launcher = json.loads(task_row["launcher_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise RuntimeError(
                        "runtime-refresh prelaunch recovery task launcher is invalid"
                    ) from exc
                if not isinstance(task_launcher, dict):
                    raise RuntimeError(
                        "runtime-refresh prelaunch recovery task launcher is invalid"
                    )
                outcome_unknown = task_launcher.get("outcome_unknown")
                if outcome_unknown not in (None, False, True):
                    raise RuntimeError(
                        "runtime-refresh prelaunch recovery task launch outcome is invalid"
                    )
                launch_returncode = task_launcher.get("returncode")
                if launch_returncode is None or outcome_unknown is True:
                    retained.append(journal["task_id"])
                    continue
                if isinstance(launch_returncode, bool) or not isinstance(
                    launch_returncode, int
                ):
                    raise RuntimeError(
                        "runtime-refresh prelaunch recovery task returncode is invalid"
                    )
                if launch_returncode == 0:
                    _delete_runtime_refresh_prelaunch_binding_journal(
                        connection, journal
                    )
                    retained.append(journal["task_id"])
                    continue
            recovery = resources.restore_runtime_refresh_executor_lease_binding_plan(
                journal["binding_plan"]
            )
''',
    "journal recovery launch-state classification",
)

tasks = replace_once(
    tasks,
    '''            _register_task_reconcile_sequence(connection, task_id)
            if executor_lease_binding_journal is not None:
                _delete_runtime_refresh_prelaunch_binding_journal(
                    connection, executor_lease_binding_journal
                )
            connection.commit()
''',
    '''            _register_task_reconcile_sequence(connection, task_id)
            connection.commit()
''',
    "retain journal through task-row persistence",
)

tasks = replace_once(
    tasks,
    '''    state = _launch_state(launcher)
    stored = _set_state(task_id, state, launcher=launcher)
    lease_maintenance = _maintain_record_resources(stored, state)
''',
    '''    state = _launch_state(launcher)
    stored = _set_state(task_id, state, launcher=launcher)
    if (
        executor_lease_binding_journal is not None
        and executor_lease_binding is not None
    ):
        if state == "running":
            with _database_connection() as connection:
                _delete_runtime_refresh_prelaunch_binding_journal(
                    connection, executor_lease_binding_journal
                )
                connection.commit()
        elif state == "failed" and launcher.get("outcome_unknown") is not True:
            executor_prelaunch_compensation = (
                resources.unbind_runtime_refresh_executor_leases(
                    executor_lease_binding
                )
            )
            with _database_connection() as connection:
                _delete_runtime_refresh_prelaunch_binding_journal(
                    connection, executor_lease_binding_journal
                )
                connection.commit()
            launcher = {
                **launcher,
                "runtime_refresh_executor_prelaunch_compensation": (
                    executor_prelaunch_compensation
                ),
            }
            stored = _set_state(task_id, state, launcher=launcher)
    lease_maintenance = _maintain_record_resources(stored, state)
''',
    "post-dispatch journal settlement",
)

tasks_path.write_text(tasks)


tests_path = Path("tests/test_tasks.py")
tests = tests_path.read_text()
marker = '''\n\n\nclass RuntimeContractTests(unittest.TestCase):\n'''
insert = r'''

    def test_runtime_refresh_live_authority_drift_precedes_pending_journal_recovery(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
            "marker": "authority-drift-pending-journal",
        }
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh authority drift pending journal",
            ttl_seconds=1200,
            metadata=metadata,
        )
        old_task_id = "c" * 24
        old_unit = f"grabowski-task-{old_task_id}-a1.service"
        old_request = tasks._runtime_refresh_prelaunch_lease_binding_request(
            fixture["request"],
            fixture["intent"],
            fixture["authority"],
            old_task_id,
            old_unit,
        )
        old_plan = tasks.resources.prepare_runtime_refresh_executor_lease_binding(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            expected_approval_task_id=fixture["approval_task_id"],
            expected_intent_sha256=fixture["intent_sha256"],
        )
        old_journal = tasks._runtime_refresh_prelaunch_binding_journal(
            old_request,
            argv_sha256="c" * 64,
            binding_plan=old_plan,
        )
        tasks._persist_runtime_refresh_prelaunch_binding_journal(old_journal)
        tasks.resources.bind_runtime_refresh_executor_leases(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            prepared_binding=old_plan,
        )

        with self._runtime_refresh_start_environment(fixture) as (dispatch_mock, _audit_mock):
            with (
                patch.object(
                    tasks.bureau_runtime_refresh_executor,
                    "load_bound_intent",
                    side_effect=[fixture["intent"], fixture["intent"]],
                ) as load_intent,
                patch.object(
                    tasks.bureau_runtime_refresh_executor,
                    "validate_authority_execution_contract",
                    side_effect=[
                        fixture["authority"],
                        PermissionError("simulated recovery authority drift"),
                    ],
                ) as validate_authority,
                patch.object(
                    tasks,
                    "_reconcile_runtime_refresh_prelaunch_binding_journals",
                    side_effect=AssertionError("journal recovery must not run"),
                ) as reconcile,
            ):
                with self.assertRaisesRegex(PermissionError, "recovery authority drift"):
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        self.assertEqual(2, load_intent.call_count)
        self.assertEqual(2, validate_authority.call_count)
        reconcile.assert_not_called()
        dispatch_mock.assert_not_called()
        self.assertEqual(
            {old_unit},
            {
                item["executor_unit"]
                for item in self._runtime_refresh_lease_metadata(
                    fixture["resource_keys"]
                ).values()
            },
        )
        with sqlite3.connect(self.database) as connection:
            journal_row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks._runtime_refresh_prelaunch_journal_key(old_task_id),),
            ).fetchone()
        self.assertIsNotNone(journal_row)

    def test_runtime_refresh_definitive_launch_failure_compensates_binding(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        original = tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh definitive launch failure",
            ttl_seconds=1200,
            metadata={
                "approval_task_id": fixture["approval_task_id"],
                "intent_sha256": fixture["intent_sha256"],
                "marker": "definitive-launch-failure",
            },
        )["leases"]
        with self._runtime_refresh_start_environment(
            fixture, dispatch_effect=lambda *_args, **_kwargs: _launcher(1)
        ) as (dispatch_mock, _audit_mock):
            started = tasks.grabowski_task_start(
                "local",
                fixture["argv"],
                cwd=str(tasks.operator.HOME),
                runtime_seconds=60,
                resume_policy="never",
            )
        self.assertEqual(1, dispatch_mock.call_count)
        self.assertEqual("failed", started["task"]["state"])
        self.assertEqual(
            original,
            [
                tasks.resources.inspect_resource(key)
                for key in fixture["resource_keys"]
            ],
        )
        self.assertTrue(
            all(
                "executor_unit" not in item
                for item in self._runtime_refresh_lease_metadata(
                    fixture["resource_keys"]
                ).values()
            )
        )
        with sqlite3.connect(self.database) as connection:
            remaining = connection.execute(
                "SELECT key FROM metadata WHERE key LIKE ?",
                (tasks.BUREAU_RUNTIME_REFRESH_PRELAUNCH_JOURNAL_KEY_PREFIX + "%",),
            ).fetchall()
        self.assertEqual([], remaining)

    def test_runtime_refresh_ambiguous_launch_retains_binding_and_journal(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh ambiguous launch",
            ttl_seconds=1200,
            metadata={
                "approval_task_id": fixture["approval_task_id"],
                "intent_sha256": fixture["intent_sha256"],
                "marker": "ambiguous-launch",
            },
        )
        ambiguous = _launcher(1)
        ambiguous["outcome_unknown"] = True
        with self._runtime_refresh_start_environment(
            fixture, dispatch_effect=lambda *_args, **_kwargs: ambiguous
        ) as (dispatch_mock, _audit_mock):
            started = tasks.grabowski_task_start(
                "local",
                fixture["argv"],
                cwd=str(tasks.operator.HOME),
                runtime_seconds=60,
                resume_policy="never",
            )
        self.assertEqual(1, dispatch_mock.call_count)
        self.assertEqual("outcome_unknown", started["task"]["state"])
        self.assertEqual(
            {started["task"]["unit"]},
            {
                item["executor_unit"]
                for item in self._runtime_refresh_lease_metadata(
                    fixture["resource_keys"]
                ).values()
            },
        )
        with sqlite3.connect(self.database) as connection:
            remaining = connection.execute(
                "SELECT key FROM metadata WHERE key LIKE ?",
                (tasks.BUREAU_RUNTIME_REFRESH_PRELAUNCH_JOURNAL_KEY_PREFIX + "%",),
            ).fetchall()
        self.assertEqual(1, len(remaining))
'''

tests = replace_once(
    tests,
    marker,
    "\n" + insert + "\n\nclass RuntimeContractTests(unittest.TestCase):\n",
    "runtime-refresh regression insertion",
)
tests_path.write_text(tests)
