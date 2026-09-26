from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import importlib
from pathlib import Path
import time
from typing import Any, Callable

import grabowski_current_work as current_work


MAX_SOURCE_TASKS = current_work.MAX_TASKS
MAX_SOURCE_LEASES = current_work.MAX_LEASES
MAX_SOURCE_WORKERS = current_work.MAX_WORKERS
CURRENT_TASK_STATES = ("launching", "running", "interrupted", "outcome_unknown")
CURRENT_WORK_GIT_TIMEOUT_SECONDS = 1.0
CURRENT_WORK_CHECKOUT_OBSERVATION_BUDGET_SECONDS = 4.0
CURRENT_WORK_CHECKOUT_MAX_WORKTREES: int | None = None
CURRENT_WORK_MAX_PARALLEL_SOURCES = 2


def _module(name: str) -> Any:
    return importlib.import_module(name)


def _operator() -> Any:
    return _module("grabowski_operator_core")


def _require_repositories(repositories: list[str]) -> list[str]:
    if not isinstance(repositories, list) or not 1 <= len(repositories) <= current_work.MAX_REPOSITORIES:
        raise ValueError(
            f"repositories must contain between 1 and {current_work.MAX_REPOSITORIES} paths"
        )
    normalized: list[str] = []
    for repository in repositories:
        if not isinstance(repository, str) or not repository or "\x00" in repository:
            raise ValueError("repository paths must be non-empty strings")
        candidate = Path(repository).expanduser()
        if not candidate.is_absolute():
            raise ValueError(
                "repository paths must be absolute; repository aliases are not accepted"
            )
        canonical = str(candidate.resolve(strict=False))
        if canonical in normalized:
            raise ValueError("repositories must resolve to unique canonical paths")
        normalized.append(canonical)
    return normalized


def _source_error(source: str, exc: Exception) -> dict[str, str]:
    return {
        "source": source,
        "error": type(exc).__name__,
    }


def _attempt_source(
    source: str,
    capability: str,
    loader: Callable[[], Any],
    errors: list[dict[str, Any]],
    default: Any,
) -> Any:
    try:
        _operator()._require_operator_capability(capability)
        return loader()
    except Exception as exc:  # Each unavailable source remains explicit and partial.
        errors.append(_source_error(source, exc))
        return default


def _task_lease_ids(payload: dict[str, Any]) -> tuple[list[str], bool]:
    leases = payload.get("leases", [])
    if not isinstance(leases, list):
        return [], True
    task_ids = sorted(
        {
            owner_id.removeprefix("task:")
            for item in leases
            if isinstance(item, dict)
            and isinstance((owner_id := item.get("owner_id")), str)
            and owner_id.startswith("task:")
            and owner_id != "task:"
        }
    )
    return task_ids[:MAX_SOURCE_TASKS], len(task_ids) > MAX_SOURCE_TASKS


def _task_payload(
    view: str,
    required_task_ids: list[str] | None = None,
    *,
    required_ids_truncated: bool = False,
) -> dict[str, Any]:
    tasks = _module("grabowski_tasks")
    projection = tasks._task_current_projection()
    required_task_ids = list(required_task_ids or [])
    with tasks._task_read_snapshot() as connection:
        if view == "current":
            placeholders = ",".join("?" for _ in CURRENT_TASK_STATES)
            current_rows = tasks._task_list_current_rows(
                connection,
                where=[f"state IN ({placeholders})"],
                parameters=list(CURRENT_TASK_STATES),
                cursor_created_at=None,
                cursor_task_id=None,
                limit=MAX_SOURCE_TASKS,
                projection=projection,
            )
            valid_required_ids = [
                task_id
                for task_id in required_task_ids[:MAX_SOURCE_TASKS]
                if isinstance(task_id, str) and tasks.TASK_ID.fullmatch(task_id) is not None
            ]
            exact_rows = []
            if valid_required_ids:
                exact_placeholders = ",".join("?" for _ in valid_required_ids)
                exact_rows = connection.execute(
                    f"SELECT * FROM tasks WHERE task_id IN ({exact_placeholders}) "
                    "ORDER BY created_at_unix DESC, task_id DESC",
                    valid_required_ids,
                ).fetchall()
            merged: list[Any] = []
            seen_task_ids: set[str] = set()
            for row in [*exact_rows, *current_rows]:
                task_id = str(row["task_id"])
                if task_id in seen_task_ids:
                    continue
                seen_task_ids.add(task_id)
                merged.append(row)
            has_more = (
                required_ids_truncated
                or len(required_task_ids) > MAX_SOURCE_TASKS
                or len(current_rows) > MAX_SOURCE_TASKS
                or len(merged) > MAX_SOURCE_TASKS
            )
            selected = merged[:MAX_SOURCE_TASKS]
            source_projection = "current-task-projection-plus-exact-active-lease-lifecycles"
        else:
            rows = connection.execute(
                "SELECT * FROM tasks ORDER BY created_at_unix DESC, task_id DESC LIMIT ?",
                (MAX_SOURCE_TASKS + 1,),
            ).fetchall()
            has_more = len(rows) > MAX_SOURCE_TASKS
            selected = rows[:MAX_SOURCE_TASKS]
            source_projection = "raw-task-ledger-window"
    return {
        "tasks": [tasks._public_for_view(dict(row), "standard") for row in selected],
        "pagination": {"has_more": has_more},
        "source_projection": source_projection,
    }


def _attention_payload(view: str) -> dict[str, Any]:
    task_attention = _module("grabowski_task_attention")
    parameters = {"limit": task_attention.MAX_PAGE_LIMIT, "view": view}
    if view == "current":
        return task_attention.reconcile_attention(
            parameters,
            _bounded_current_projection=True,
        )
    return task_attention.reconcile_attention(parameters)


def _resources_payload() -> dict[str, Any]:
    resources = _module("grabowski_resources")
    leases = resources.list_resources(
        include_expired=False,
        limit=MAX_SOURCE_LEASES,
    )
    total = resources.count_resources(include_expired=False)
    return {
        "leases": leases,
        "count": total,
        "truncated": total > len(leases),
    }


def _checkout_payloads(
    repositories: list[str],
    errors: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    checkouts = _module("grabowski_checkouts")
    payloads: list[dict[str, Any]] = []
    for repository in repositories:
        try:
            payload = checkouts.checkout_inventory(
                repository,
                include_processes=False,
                include_tasks=False,
                include_resources=True,
                git_timeout_seconds=CURRENT_WORK_GIT_TIMEOUT_SECONDS,
                observation_budget_seconds=(
                    CURRENT_WORK_CHECKOUT_OBSERVATION_BUDGET_SECONDS
                ),
                max_worktrees=CURRENT_WORK_CHECKOUT_MAX_WORKTREES,
            )
            payloads.append(payload)
            if payload.get("truncated") is True and errors is not None:
                errors.append(
                    {
                        "source": "checkouts",
                        "repository": repository,
                        "error": "CheckoutObservationPartial",
                        "omitted_worktree_count": int(
                            payload.get("omitted_worktree_count", 0) or 0
                        ),
                        "probe_error_count": len(
                            payload.get("probe_errors", [])
                            if isinstance(payload.get("probe_errors"), list)
                            else []
                        ),
                    }
                )
        except Exception as exc:
            if errors is None:
                raise
            error = _source_error("checkouts", exc)
            error["repository"] = repository
            errors.append(error)
            payloads.append(
                {"repository": repository, "worktrees": [], "truncated": True}
            )
    return payloads


def _reconciliation_payload(repositories: list[str]) -> dict[str, Any]:
    reconciler = _module("grabowski_checkout_binding_reconciler")
    return reconciler.reconcile_checkout_bindings(
        repository_filters=repositories,
        limit=reconciler.MAX_PAGE_LIMIT,
        git_timeout_seconds=CURRENT_WORK_GIT_TIMEOUT_SECONDS,
    )


def _tmux_payload() -> dict[str, Any]:
    return _operator().grabowski_tmux_list()


def _process_payload() -> dict[str, Any]:
    return _operator().grabowski_process_list()


def _worker_payload(kind: str, view: str) -> dict[str, Any]:
    workers = _module("grabowski_workers")
    return workers.worker_list(kind, MAX_SOURCE_WORKERS, view=view)


def _collect_independent_source(
    source: str,
    capability: str,
    loader: Callable[[list[dict[str, Any]]], Any],
    default: Any,
) -> tuple[Any, list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    value = _attempt_source(
        source,
        capability,
        lambda: loader(errors),
        errors,
        default,
    )
    return value, errors


def grabowski_current_work(
    repositories: list[str],
    view: str = "current",
    limit: int = 20,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Project global operator work plus repository-filtered Git checkout surfaces."""
    repository_filters = _require_repositories(repositories)
    if view not in current_work.CURRENT_WORK_VIEWS:
        raise ValueError("view must be current or history")

    source_errors: list[dict[str, Any]] = []
    independent_sources = [
        (
            "checkouts",
            "git_cli",
            lambda errors: _checkout_payloads(repository_filters, errors),
            [
                {"repository": repository, "worktrees": [], "truncated": True}
                for repository in repository_filters
            ],
        ),
        (
            "tmux",
            "tmux_interaction",
            lambda _errors: _tmux_payload(),
            {"returncode": 1, "stdout": ""},
        ),
        (
            "processes",
            "process_inspect",
            lambda _errors: _process_payload(),
            {"returncode": 1, "lines": []},
        ),
        (
            "browser_workers",
            "browser_worker",
            lambda _errors: _worker_payload("browser", view),
            {"workers": [], "has_more": True},
        ),
        (
            "gui_workers",
            "gui_worker",
            lambda _errors: _worker_payload("gui", view),
            {"workers": [], "has_more": True},
        ),
    ]
    source_order = [
        "attention",
        "checkouts",
        "checkout_binding_reconciliation",
        "tmux",
        "processes",
        "browser_workers",
        "gui_workers",
    ]

    with ThreadPoolExecutor(
        max_workers=min(CURRENT_WORK_MAX_PARALLEL_SOURCES, len(independent_sources)),
        thread_name_prefix="grabowski-current-work",
    ) as executor:
        futures = {
            source: executor.submit(
                _collect_independent_source,
                source,
                capability,
                loader,
                default,
            )
            for source, capability, loader, default in independent_sources
        }

        # Resource leases determine which exact task lifecycles must be retained,
        # so this dependency stays ordered while independent sources overlap it.
        resources_payload = _attempt_source(
            "resources",
            "resource_lease",
            _resources_payload,
            source_errors,
            {"leases": [], "count": 0, "truncated": True},
        )
        lease_task_ids, lease_task_ids_truncated = _task_lease_ids(resources_payload)
        tasks_payload = _attempt_source(
            "tasks",
            "durable_job",
            lambda: _task_payload(
                view,
                lease_task_ids,
                required_ids_truncated=lease_task_ids_truncated,
            ),
            source_errors,
            {"tasks": [], "pagination": {"has_more": True}},
        )

        # Attention derives from the same task store. Preserve the historical
        # tasks -> attention ordering so an older attention generation cannot
        # be joined onto a newer task snapshot.
        attention_result = _collect_independent_source(
            "attention",
            "durable_job",
            lambda _errors: _attention_payload(view),
            {"records": [], "pagination": {"has_more": True}},
        )

        # Checkout inventory and binding reconciliation share checkout-binding
        # storage. Keep that pair ordered while still overlapping it with the
        # other independent read surfaces.
        independent_results = {
            "attention": attention_result,
            "checkouts": futures["checkouts"].result(),
        }
        reconciliation_future = executor.submit(
            _collect_independent_source,
            "checkout_binding_reconciliation",
            "git_cli",
            lambda _errors: _reconciliation_payload(repository_filters),
            {
                "bindings": [],
                "pagination": {"has_more": True},
                "total_count": 0,
            },
        )
        for source, future in futures.items():
            if source == "checkouts":
                continue
            independent_results[source] = future.result()
        independent_results["checkout_binding_reconciliation"] = (
            reconciliation_future.result()
        )

    independent_payloads: dict[str, Any] = {}
    for source in source_order:
        payload, errors = independent_results[source]
        independent_payloads[source] = payload
        source_errors.extend(errors)

    attention_payload = independent_payloads["attention"]
    checkout_payloads = independent_payloads["checkouts"]
    reconciliation_payload = independent_payloads["checkout_binding_reconciliation"]
    tmux_payload = independent_payloads["tmux"]
    process_payload = independent_payloads["processes"]
    browser_payload = independent_payloads["browser_workers"]
    gui_payload = independent_payloads["gui_workers"]

    return current_work.build_current_work_projection(
        tasks_payload=tasks_payload,
        attention_payload=attention_payload,
        resources_payload=resources_payload,
        checkout_payloads=checkout_payloads,
        repository_filters=repository_filters,
        tmux_payload=tmux_payload,
        process_payload=process_payload,
        browser_payload=browser_payload,
        gui_payload=gui_payload,
        source_errors=source_errors,
        generated_at_unix=int(time.time()),
        reconciliation_payload=reconciliation_payload,
        view=view,
        limit=limit,
        cursor=cursor,
    )
