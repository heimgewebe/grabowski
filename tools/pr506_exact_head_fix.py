#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import textwrap


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "src" / "grabowski_tasks.py"
TESTS_PATH = ROOT / "tests" / "test_tasks.py"


def replace_function(text: str, name: str, replacement: str) -> str:
    start = text.index(f"def {name}(")
    end = text.find("\n\ndef ", start + 1)
    if end < 0:
        raise RuntimeError(f"could not find end of {name}")
    return text[:start] + replacement.rstrip() + text[end:]


def main() -> int:
    source = SOURCE_PATH.read_text(encoding="utf-8")
    tests = TESTS_PATH.read_text(encoding="utf-8")

    constant_anchor = "MAX_BUILD_SCRIPT_INSPECTION_BYTES = 256 * 1024\n"
    constant_line = "MANAGED_CARGO_ATTENTION_MATCH_LIMIT = 50_000\n"
    if constant_line not in source:
        if source.count(constant_anchor) != 1:
            raise RuntimeError("managed Cargo limit anchor is ambiguous")
        source = source.replace(constant_anchor, constant_anchor + constant_line, 1)

    helper = textwrap.dedent(
        '''
        def _managed_cargo_command_sql_predicate(
            command: list[str],
        ) -> tuple[str, tuple[Any, ...]]:
            if not command or any(not isinstance(item, str) for item in command):
                raise ValueError("managed Cargo command must contain only strings")

            clauses = ["argv_json=?"]
            parameters: list[Any] = [_canonical_json(command)]
            explicit_target = _explicit_managed_cargo_target_dir(command)
            if explicit_target is not None:
                clauses.append("argv_json=?")
                parameters.append(
                    _canonical_json(
                        [
                            FLOCK_EXECUTABLE,
                            "--shared",
                            str(_managed_cargo_lifecycle_lock_path(explicit_target)),
                            *command,
                        ]
                    )
                )

            target_prefix = "CARGO_TARGET_DIR="
            wrapper_terms = [
                "json_valid(argv_json)",
                "json_type(argv_json)='array'",
                "json_array_length(argv_json)=?",
                "json_type(argv_json, '$[0]')='text'",
                "json_extract(argv_json, '$[0]')=?",
                "json_type(argv_json, '$[1]')='text'",
                "json_extract(argv_json, '$[1]')=?",
                "json_type(argv_json, '$[2]')='text'",
                "json_type(argv_json, '$[3]')='text'",
                "(json_extract(argv_json, '$[3]')=? "
                "OR json_extract(argv_json, '$[3]') GLOB '*/env')",
                "json_type(argv_json, '$[4]')='text'",
                "substr(json_extract(argv_json, '$[4]'), 1, ?)=?",
            ]
            wrapper_parameters: list[Any] = [
                len(command) + 5,
                FLOCK_EXECUTABLE,
                "--shared",
                Path(SYSTEMD_ENV_EXECUTABLE).name,
                len(target_prefix),
                target_prefix,
            ]
            for index, item in enumerate(command, start=5):
                wrapper_terms.extend(
                    [
                        f"json_type(argv_json, '$[{index}]')='text'",
                        f"json_extract(argv_json, '$[{index}]')=?",
                    ]
                )
                wrapper_parameters.append(item)
            clauses.append("(" + " AND ".join(wrapper_terms) + ")")
            parameters.extend(wrapper_parameters)

            # Preserve the old fail-closed behavior for corrupt stored argv.
            # CASE prevents JSON table functions from evaluating malformed JSON.
            invalid_stored_argv = (
                "CASE WHEN NOT json_valid(argv_json) THEN 1 "
                "WHEN json_type(argv_json)<>'array' THEN 1 "
                "WHEN EXISTS (SELECT 1 FROM json_each(argv_json) WHERE type<>'text') "
                "THEN 1 ELSE 0 END=1"
            )
            clauses.append(invalid_stored_argv)
            return (
                "(" + " OR ".join(f"({clause})" for clause in clauses) + ")",
                tuple(parameters),
            )
        '''
    ).strip()

    marker = "def _latest_matching_unprepared_managed_cargo_record("
    if "def _managed_cargo_command_sql_predicate(" not in source:
        position = source.index(marker)
        source = source[:position] + helper + "\n\n\n" + source[position:]

    latest = textwrap.dedent(
        '''
        def _latest_matching_unprepared_managed_cargo_record(
            identity: dict[str, Any],
            command: list[str],
        ) -> dict[str, Any] | None:
            argv_predicate, argv_parameters = _managed_cargo_command_sql_predicate(command)
            with _database_connection() as connection:
                cursor = connection.execute(
                    "SELECT * FROM tasks WHERE host=? AND cwd=? "
                    "AND resource_keys_json=? AND runtime_seconds=? AND cpu_weight=? "
                    "AND io_weight=? AND memory_max_bytes IS ? "
                    "AND chronik_outbox_enabled=? AND chronik_outbox_state_root IS ? "
                    "AND chronik_context_json IS ? AND execution_backend=? AND systemd_scope=? "
                    f"AND {argv_predicate} "
                    "ORDER BY created_at_unix DESC, rowid DESC",
                    (
                        identity["host"],
                        identity["cwd"],
                        _canonical_json(identity["resource_keys"]),
                        identity["runtime_seconds"],
                        identity["cpu_weight"],
                        identity["io_weight"],
                        identity["memory_max_bytes"],
                        int(identity["chronik_outbox_enabled"]),
                        identity["chronik_outbox_state_root"],
                        (
                            _canonical_json(identity["chronik_context"])
                            if identity["chronik_context"] is not None
                            else None
                        ),
                        identity["execution_backend"],
                        identity["systemd_scope"],
                        *argv_parameters,
                    ),
                )
                while True:
                    rows = cursor.fetchmany(256)
                    if not rows:
                        return None
                    for row in rows:
                        record = dict(row)
                        if _record_matches_unprepared_managed_cargo_command(
                            record, command
                        ):
                            return record
        '''
    ).strip()

    matching = textwrap.dedent(
        '''
        def _matching_attention_unprepared_managed_cargo_records(
            identity: dict[str, Any],
            command: list[str],
        ) -> list[dict[str, Any]]:
            attention_states = tuple(TASK_STATE_PROJECTIONS["attention"])
            placeholders = ",".join("?" for _ in attention_states)
            argv_predicate, argv_parameters = _managed_cargo_command_sql_predicate(command)
            scan_limit = MANAGED_CARGO_ATTENTION_MATCH_LIMIT
            if (
                isinstance(scan_limit, bool)
                or not isinstance(scan_limit, int)
                or scan_limit < 1
            ):
                raise RuntimeError("managed Cargo attention scan limit is invalid")
            with _database_connection() as connection:
                rows = connection.execute(
                    "SELECT * FROM tasks WHERE host=? AND cwd=? "
                    "AND resource_keys_json=? AND runtime_seconds=? AND cpu_weight=? "
                    "AND io_weight=? AND memory_max_bytes IS ? "
                    "AND chronik_outbox_enabled=? AND chronik_outbox_state_root IS ? "
                    "AND chronik_context_json IS ? AND execution_backend=? AND systemd_scope=? "
                    f"AND {argv_predicate} "
                    f"AND state IN ({placeholders}) "
                    "ORDER BY created_at_unix DESC, rowid DESC LIMIT ?",
                    (
                        identity["host"],
                        identity["cwd"],
                        _canonical_json(identity["resource_keys"]),
                        identity["runtime_seconds"],
                        identity["cpu_weight"],
                        identity["io_weight"],
                        identity["memory_max_bytes"],
                        int(identity["chronik_outbox_enabled"]),
                        identity["chronik_outbox_state_root"],
                        (
                            _canonical_json(identity["chronik_context"])
                            if identity["chronik_context"] is not None
                            else None
                        ),
                        identity["execution_backend"],
                        identity["systemd_scope"],
                        *argv_parameters,
                        *attention_states,
                        scan_limit + 1,
                    ),
                ).fetchall()
            if len(rows) > scan_limit:
                raise RuntimeError("matching managed Cargo attention scan limit exceeded")
            return [
                record
                for row in rows
                if _record_matches_unprepared_managed_cargo_command(
                    record := dict(row), command
                )
            ]
        '''
    ).strip()

    source = replace_function(
        source,
        "_latest_matching_unprepared_managed_cargo_record",
        latest,
    )
    source = replace_function(
        source,
        "_matching_attention_unprepared_managed_cargo_records",
        matching,
    )

    tests_block = textwrap.dedent(
        '''
            def test_managed_cargo_attention_limit_counts_only_command_matches(self) -> None:
                raw_command = ["/usr/bin/cargo", "test"]

                def start_failed(command: list[str], cache_key: str) -> dict[str, object]:
                    target_dir = tasks.MANAGED_CARGO_CACHE_ROOT / cache_key / "target"
                    lifecycle_lock = tasks.MANAGED_CARGO_LOCK_ROOT / f"{cache_key}.lock"
                    bound = [
                        tasks.FLOCK_EXECUTABLE,
                        "--shared",
                        str(lifecycle_lock),
                        tasks.SYSTEMD_ENV_EXECUTABLE,
                        f"CARGO_TARGET_DIR={target_dir}",
                        *command,
                    ]
                    with (
                        patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                        patch.object(
                            tasks, "_managed_cargo_request_root", return_value=self.root
                        ),
                        patch.object(
                            tasks, "_bind_managed_cargo_environment", return_value=bound
                        ),
                        patch.object(tasks, "_dispatch", return_value=_launcher()),
                        patch.object(tasks.base, "_append_audit"),
                        patch.object(
                            tasks,
                            "_require_recovery_gate",
                            return_value={"checked_at_unix": 123},
                        ),
                    ):
                        started = tasks.grabowski_task_start(
                            "local",
                            command,
                            cwd=str(self.root),
                            runtime_seconds=60,
                            resume_policy="retry-safe",
                            cpu_weight=50,
                            io_weight=25,
                        )["task"]
                    return tasks._set_state(
                        str(started["task_id"]),
                        "failed",
                        observation={"state": "failed", "source": "test"},
                    )

                relevant = start_failed(raw_command, "a" * 64)
                start_failed(["/usr/bin/cargo", "check"], "b" * 64)
                start_failed(["/usr/bin/cargo", "clippy"], "c" * 64)
                identity = tasks._task_execution_identity(
                    host="local",
                    argv_sha256=tasks.command_identity.argv_sha256(raw_command),
                    cwd=str(self.root),
                    resource_keys=[],
                    runtime_seconds=60,
                    cpu_weight=50,
                    io_weight=25,
                    memory_max_bytes=None,
                    chronik_outbox_enabled=False,
                    chronik_outbox_state_root=None,
                    chronik_context_json=None,
                    execution_backend="systemd-user",
                    systemd_scope="user",
                )
                with patch.object(tasks, "MANAGED_CARGO_ATTENTION_MATCH_LIMIT", 1):
                    records = tasks._matching_attention_unprepared_managed_cargo_records(
                        identity, raw_command
                    )
                self.assertEqual(
                    [relevant["task_id"]],
                    [item["task_id"] for item in records],
                )

                duplicate = dict(tasks._row_raw(str(relevant["task_id"])))
                duplicate["task_id"] = "f" * 24
                duplicate["unit"] = tasks._task_unit(duplicate["task_id"], 1)
                duplicate["authoritative_unit"] = duplicate["unit"]
                duplicate["lease_owner_id"] = f"task:{duplicate['task_id']}"
                duplicate["created_at_unix"] = int(duplicate["created_at_unix"]) + 1
                duplicate["updated_at_unix"] = int(duplicate["updated_at_unix"]) + 1
                columns = tuple(duplicate)
                with tasks._database() as connection:
                    connection.execute(
                        f"INSERT INTO tasks ({','.join(columns)}) VALUES "
                        f"({','.join('?' for _ in columns)})",
                        tuple(duplicate[column] for column in columns),
                    )
                    connection.commit()
                with (
                    patch.object(tasks, "MANAGED_CARGO_ATTENTION_MATCH_LIMIT", 1),
                    self.assertRaisesRegex(RuntimeError, "scan limit exceeded"),
                ):
                    tasks._matching_attention_unprepared_managed_cargo_records(
                        identity, raw_command
                    )

            def test_managed_cargo_attention_scan_keeps_corrupt_argv_fail_closed(self) -> None:
                raw_command = ["/usr/bin/cargo", "test"]
                relevant = self._start()["task"]
                task_id = str(relevant["task_id"])
                tasks._set_state(
                    task_id,
                    "failed",
                    observation={"state": "failed", "source": "test"},
                )
                with tasks._database() as connection:
                    connection.execute(
                        "UPDATE tasks SET argv_json='{' WHERE task_id=?",
                        (task_id,),
                    )
                    connection.commit()
                identity = tasks._task_execution_identity(
                    host="local",
                    argv_sha256=tasks.command_identity.argv_sha256(raw_command),
                    cwd=str(self.root),
                    resource_keys=[],
                    runtime_seconds=60,
                    cpu_weight=50,
                    io_weight=25,
                    memory_max_bytes=64 * 1024 * 1024,
                    chronik_outbox_enabled=False,
                    chronik_outbox_state_root=None,
                    chronik_context_json=None,
                    execution_backend="systemd-user",
                    systemd_scope="user",
                )
                with self.assertRaisesRegex(RuntimeError, "stored task argv is invalid"):
                    tasks._matching_attention_unprepared_managed_cargo_records(
                        identity, raw_command
                    )

        '''
    )
    test_anchor = (
        "    def test_task_start_blocks_unchanged_terminal_failure_without_named_change"
        "(self) -> None:\n"
    )
    if "def test_managed_cargo_attention_limit_counts_only_command_matches" not in tests:
        if tests.count(test_anchor) != 1:
            raise RuntimeError("managed Cargo test anchor is ambiguous")
        tests = tests.replace(test_anchor, tests_block + test_anchor, 1)

    SOURCE_PATH.write_text(source, encoding="utf-8")
    TESTS_PATH.write_text(tests, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
