from __future__ import annotations

from pathlib import Path
import ast
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_work_admission as admission


class WorkAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _main(self, *, dirty: bool = False) -> dict[str, object]:
        return {
            "path": str(self.repo),
            "is_main": True,
            "branch": "main",
            "status": {"dirty": dirty},
            "coordination": {
                "resource_leases": [],
                "tasks": [],
                "processes": [],
            },
            "lifecycle": {},
            "lifecycle_state": "main",
        }

    def _linked(
        self,
        *,
        state: str,
        dirty: bool = False,
        owner: str | None = None,
        source_id: str | None = None,
        foreign_lease: bool = False,
    ) -> dict[str, object]:
        lifecycle: dict[str, object] = {}
        if owner is not None or source_id is not None:
            lifecycle["binding"] = {
                "owner_id": owner,
                "source_kind": "bureau_task",
                "source_id": source_id,
            }
        return {
            "path": str(self.repo.parent / "worktrees" / state),
            "is_main": False,
            "branch": f"feat/{state}",
            "status": {"dirty": dirty},
            "coordination": {
                "resource_leases": (
                    [
                        {
                            "blocking": True,
                            "resource_key": "path:/foreign",
                            "owner_id": "foreign-owner",
                        }
                    ]
                    if foreign_lease
                    else []
                ),
                "tasks": [],
                "processes": [],
            },
            "lifecycle": lifecycle,
            "lifecycle_state": state,
        }

    @staticmethod
    def _reconciliation(
        *, blocking: bool = False, truncated: bool = False
    ) -> dict[str, object]:
        return {
            "bindings": (
                [
                    {
                        "blocking": True,
                        "checkout_key": "abc",
                        "state": "orphaned",
                        "reasons": ["bound checkout missing"],
                    }
                ]
                if blocking
                else []
            ),
            "pagination": {"has_more": truncated},
            "source_snapshot": {"repository_errors": []},
            "snapshot_sha256": "b" * 64,
        }

    def _assess(
        self,
        worktrees: list[dict[str, object]],
        *,
        reconciliation: dict[str, object] | None = None,
        **kwargs: object,
    ) -> dict[str, object]:
        return admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="worktree_create",
            inventory_loader=lambda _repo: {
                "worktrees": worktrees,
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: (
                reconciliation or self._reconciliation()
            ),
            **kwargs,
        )

    def test_every_checkout_lifecycle_state_has_an_admission_policy(self) -> None:
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "grabowski_checkouts.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        classifier = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_checkout_lifecycle_decision"
        )
        emitted_states = {
            node.value.value
            for node in ast.walk(classifier)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "state"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        }
        explicitly_handled = (
            set(admission.CONVERGENCE_STATES)
            | set(admission.TERMINAL_NONBLOCKING_STATES)
            | {
                "main",
                "dirty",
                "retained",
            }
        )
        self.assertEqual(emitted_states, explicitly_handled)

    def test_external_terminal_missing_is_not_live_work_or_convergence(self) -> None:
        terminal = self._linked(
            state="externally_terminal_missing",
            owner="foreign-historical-owner",
            source_id="terminal-source",
        )
        result = self._assess(
            [self._main(), terminal],
            source_kind="bureau_task",
            source_id="terminal-source",
        )
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["blockers"], [])
        self.assertNotIn("similar-active-source-binding", result["blocker_codes"])
        self.assertIn("cleanup authority", result["does_not_establish"])

    def test_clean_primary_only_allows_new_broad_lane(self) -> None:
        result = self._assess([self._main()])
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["blockers"], [])
        self.assertTrue(result["read_only"])
        self.assertEqual(len(result["assessment_sha256"]), 64)

    def test_dirty_or_foreign_live_work_blocks_fail_closed(self) -> None:
        dirty = self._assess(
            [self._main(), self._linked(state="retained", dirty=True, owner="owner-a")]
        )
        foreign = self._assess(
            [
                self._main(),
                self._linked(
                    state="retained",
                    owner="foreign-owner",
                    foreign_lease=True,
                ),
            ]
        )
        self.assertEqual(dirty["decision"], "blocked")
        self.assertIn("dirty-worktree", dirty["blocker_codes"])
        self.assertEqual(foreign["decision"], "blocked")
        self.assertIn("foreign-live-coordination", foreign["blocker_codes"])
        self.assertIn("foreign-retained-worktree", foreign["blocker_codes"])

    def test_exact_disjoint_checkout_ignores_unrelated_repository_hygiene(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "fresh-target")
        branch = "fix/fresh-target"
        unrelated = self._linked(
            state="managed_lifecycle_drift",
            dirty=True,
            owner="foreign-owner",
            foreign_lease=True,
        )
        reconciliation = {
            "bindings": [
                {
                    "blocking": True,
                    "checkout_key": "unrelated",
                    "state": "orphaned_binding",
                    "reasons": ["binding-has-no-current-git-worktree-record"],
                    "binding_identity": {
                        "checkout_path": str(self.repo.parent / "worktrees" / "old"),
                        "expected_branch": "fix/old",
                    },
                    "evidence": {
                        "source": {"kind": "bureau-task", "id": "OLD-TASK"}
                    },
                }
            ],
            "pagination": {"has_more": False},
            "source_snapshot": {"repository_errors": []},
            "snapshot_sha256": "b" * 64,
        }

        result = self._assess(
            [self._main(dirty=True), unrelated],
            reconciliation=reconciliation,
            requested_scope={"paths": [target_path], "branch": branch},
            target_path=target_path,
            branch=branch,
            source_kind="bureau_task",
            source_id="NEW-TASK",
        )

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["scope_mode"], "exact_checkout")
        self.assertEqual(result["blockers"], [])

    def test_exact_checkout_still_blocks_target_overlap(self) -> None:
        target = self._linked(
            state="retained",
            dirty=True,
            owner="foreign-owner",
            foreign_lease=True,
        )
        target_path = str(target["path"])
        branch = str(target["branch"])

        result = self._assess(
            [self._main(), target],
            requested_scope={"paths": [target_path], "branch": branch},
            target_path=target_path,
            branch=branch,
            source_kind="bureau_task",
            source_id="NEW-TASK",
        )

        self.assertEqual(result["decision"], "blocked")
        self.assertIn("dirty-worktree", result["blocker_codes"])
        self.assertIn("foreign-live-coordination", result["blocker_codes"])
        self.assertIn("foreign-retained-worktree", result["blocker_codes"])

    def test_exact_checkout_still_blocks_same_branch_and_source(self) -> None:
        existing = self._linked(
            state="retained",
            owner="owner-a",
            source_id="SAME-TASK",
        )
        target_path = str(self.repo.parent / "worktrees" / "fresh-target")
        branch = str(existing["branch"])

        result = self._assess(
            [self._main(), existing],
            requested_scope={"paths": [target_path], "branch": branch},
            target_path=target_path,
            branch=branch,
            source_kind="bureau_task",
            source_id="SAME-TASK",
        )

        self.assertEqual(result["decision"], "converge_first")
        self.assertIn("branch-already-bound", result["blocker_codes"])
        self.assertIn("similar-active-source-binding", result["blocker_codes"])

    def test_exact_checkout_still_blocks_matching_reconciliation(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "fresh-target")
        branch = "fix/fresh-target"
        reconciliation = {
            "bindings": [
                {
                    "blocking": True,
                    "checkout_key": "target",
                    "state": "binding_identity_drift",
                    "reasons": ["expected-branch-mismatch"],
                    "binding_identity": {
                        "checkout_path": target_path,
                        "expected_branch": branch,
                    },
                }
            ],
            "pagination": {"has_more": False},
            "source_snapshot": {"repository_errors": []},
            "snapshot_sha256": "b" * 64,
        }

        result = self._assess(
            [self._main()],
            reconciliation=reconciliation,
            requested_scope={"paths": [target_path], "branch": branch},
            target_path=target_path,
            branch=branch,
            source_kind="bureau_task",
            source_id="NEW-TASK",
        )

        self.assertEqual(result["decision"], "converge_first")
        self.assertIn("binding-reconciliation-blocking", result["blocker_codes"])

    def test_existing_task_checkout_allows_exact_clean_feature_scope(self) -> None:
        target = self._linked(
            state="managed_active_attention",
            owner="workspace-owner",
        )
        target["head"] = "a" * 40
        target["detached"] = False
        target_path = str(target["path"])
        branch = str(target["branch"])
        scope = {
            "schema_version": 1,
            "repository": str(self.repo),
            "worktree": target_path,
            "head": "a" * 40,
            "branch": branch,
            "resource_keys": [
                f"path:{target_path}",
                f"repo:{self.repo}:branch:{branch}",
            ],
        }
        unrelated = self._linked(
            state="completed_retained",
            dirty=True,
            owner="foreign-owner",
            foreign_lease=True,
        )
        unrelated["head"] = "b" * 40
        unrelated["detached"] = False

        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="task:abc",
            operation="task_existing_checkout",
            requested_scope=scope,
            target_path=target_path,
            branch=branch,
            inventory_loader=lambda _repo: {
                "worktrees": [self._main(dirty=True), target, unrelated],
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: self._reconciliation(),
        )

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["scope_mode"], "exact_checkout")
        self.assertEqual(
            result["scope_identity"],
            {"target_path": target_path, "branch": branch, "head": "a" * 40},
        )
        self.assertEqual(result["blockers"], [])

    def test_existing_task_checkout_fails_closed_on_target_drift_or_foreign_live_work(self) -> None:
        for mutation, expected_code in (
            ({"status": {"dirty": True}}, "dirty-worktree"),
            ({"head": "b" * 40}, "target-head-mismatch"),
            ({"branch": "feat/other"}, "target-branch-mismatch"),
            ({"detached": True, "branch": None}, "target-checkout-detached"),
        ):
            target = self._linked(
                state="managed_active_attention",
                owner="workspace-owner",
            )
            target["head"] = "a" * 40
            target["detached"] = False
            target.update(mutation)
            target_path = str(target["path"])
            expected_branch = "feat/managed_active_attention"
            scope = {
                "schema_version": 1,
                "repository": str(self.repo),
                "worktree": target_path,
                "head": "a" * 40,
                "branch": expected_branch,
                "resource_keys": [
                    f"path:{target_path}",
                    f"repo:{self.repo}:branch:{expected_branch}",
                ],
            }
            result = admission.assess_repository_admission(
                repo=str(self.repo),
                owner_id="task:abc",
                operation="task_existing_checkout",
                requested_scope=scope,
                target_path=target_path,
                branch=expected_branch,
                inventory_loader=lambda _repo, target=target: {
                    "worktrees": [self._main(), target],
                    "inventory_sha256": "a" * 64,
                },
                reconciliation_loader=lambda _repo: self._reconciliation(),
            )
            self.assertEqual(result["decision"], "blocked")
            self.assertIn(expected_code, result["blocker_codes"])

        foreign = self._linked(
            state="managed_active_attention",
            owner="workspace-owner",
            foreign_lease=True,
        )
        foreign["head"] = "a" * 40
        foreign["detached"] = False
        target_path = str(foreign["path"])
        branch = str(foreign["branch"])
        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="task:abc",
            operation="task_existing_checkout",
            requested_scope={
                "schema_version": 1,
                "repository": str(self.repo),
                "worktree": target_path,
                "head": "a" * 40,
                "branch": branch,
                "resource_keys": [
                    f"path:{target_path}",
                    f"repo:{self.repo}:branch:{branch}",
                ],
            },
            target_path=target_path,
            branch=branch,
            inventory_loader=lambda _repo: {
                "worktrees": [self._main(), foreign],
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: self._reconciliation(),
        )
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("foreign-live-coordination", result["blocker_codes"])

    def test_existing_task_checkout_requires_exact_path_and_branch_lease_binding(self) -> None:
        target = self._linked(state="retained", owner="workspace-owner")
        target["head"] = "a" * 40
        target["detached"] = False
        target_path = str(target["path"])
        branch = str(target["branch"])
        for resource_keys in (
            [f"path:{target_path}"],
            [f"repo:{self.repo}:branch:{branch}"],
        ):
            result = admission.assess_repository_admission(
                repo=str(self.repo),
                owner_id="task:abc",
                operation="task_existing_checkout",
                requested_scope={
                    "schema_version": 1,
                    "repository": str(self.repo),
                    "worktree": target_path,
                    "head": "a" * 40,
                    "branch": branch,
                    "resource_keys": resource_keys,
                },
                target_path=target_path,
                branch=branch,
                inventory_loader=lambda _repo: {
                    "worktrees": [self._main(dirty=True), target],
                    "inventory_sha256": "a" * 64,
                },
                reconciliation_loader=lambda _repo: self._reconciliation(),
            )
            self.assertEqual(result["scope_mode"], "repository")
            self.assertEqual(result["decision"], "blocked")

    def test_exact_agent_workspace_ignores_unrelated_repository_hygiene(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "agent-target")
        branch = "fix/agent-target"
        unrelated = self._linked(
            state="completed_retained",
            dirty=True,
            owner="foreign-owner",
            foreign_lease=True,
        )

        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="agent_workspace_create",
            requested_scope={
                "allowed_paths": ["src/example.py"],
                "forbidden_paths": ["src/foreign.py"],
                "branch": branch,
            },
            target_path=target_path,
            branch=branch,
            source_kind="operator-obligation",
            source_id="NEW-OBLIGATION",
            inventory_loader=lambda _repo: {
                "worktrees": [self._main(dirty=True), unrelated],
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: {
                "bindings": [
                    {
                        "blocking": True,
                        "checkout_key": "unrelated",
                        "state": "orphaned",
                        "reasons": ["bound checkout missing"],
                        "binding_identity": {
                            "checkout_path": str(
                                self.repo.parent / "worktrees" / "old"
                            ),
                            "expected_branch": "fix/old",
                        },
                    }
                ],
                "pagination": {"has_more": False},
                "source_snapshot": {"repository_errors": []},
                "snapshot_sha256": "b" * 64,
            },
        )

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["scope_mode"], "exact_checkout")
        self.assertEqual(result["blockers"], [])

    def test_exact_checkout_fails_closed_on_unidentifiable_reconciliation(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "fresh-target")
        branch = "fix/fresh-target"

        result = self._assess(
            [self._main()],
            reconciliation=self._reconciliation(blocking=True),
            requested_scope={"paths": [target_path], "branch": branch},
            target_path=target_path,
            branch=branch,
        )

        self.assertEqual(result["decision"], "converge_first")
        self.assertIn("binding-reconciliation-blocking", result["blocker_codes"])

    def test_incomplete_checkout_scope_remains_repository_wide(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "fresh-target")
        branch = "fix/fresh-target"

        result = self._assess(
            [self._main(dirty=True)],
            requested_scope={"branch": branch},
            target_path=target_path,
            branch=branch,
        )

        self.assertEqual(result["scope_mode"], "repository")
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("dirty-worktree", result["blocker_codes"])

    def test_scoped_broad_repository_lease_ignores_unrelated_hygiene(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "bureau-target")
        branch = "feat/bureau-target"
        scope = {
            "schema_version": 1,
            "repository": str(self.repo),
            "task_id": "REPOGROUND-TEST-T005",
            "base_head": "0" * 40,
            "head": "a" * 40,
            "branch": branch,
            "worktree": target_path,
            "effects": ["write"],
            "paths": [
                str(self.repo / "src" / "example.py"),
                str(self.repo / "tests" / "test_example.py"),
            ],
            "components": [],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            requested_scope=scope,
            inventory_loader=lambda _repo: {
                "worktrees": [
                    self._main(dirty=True),
                    self._linked(
                        state="retained",
                        dirty=True,
                        owner="foreign-owner",
                        foreign_lease=True,
                    ),
                ],
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: self._reconciliation(),
        )

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["scope_mode"], "exact_checkout")
        self.assertEqual(
            result["scope_identity"],
            {"target_path": target_path, "branch": branch},
        )

        for invalid_scope in (
            {**scope, "isolation": "worktree"},
            {**scope, "paths": []},
            {
                **scope,
                "effects": ["deploy"],
                "deployments": ["production"],
                "shared_gates": ["repository-runtime-deploy"],
            },
        ):
            blocked = admission.assess_repository_admission(
                repo=str(self.repo),
                owner_id="owner-a",
                operation="broad_repository_lease",
                requested_scope=invalid_scope,
                inventory_loader=lambda _repo: {
                    "worktrees": [self._main(dirty=True)],
                    "inventory_sha256": "a" * 64,
                },
                reconciliation_loader=lambda _repo: self._reconciliation(),
            )
            self.assertEqual(blocked["scope_mode"], "repository")
            self.assertEqual(blocked["decision"], "blocked")
            self.assertIn("dirty-worktree", blocked["blocker_codes"])

    def test_exact_scope_assesses_complete_inventory_above_legacy_bound(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "bureau-target")
        branch = "feat/bureau-target"
        scope = {
            "schema_version": 1,
            "repository": str(self.repo),
            "task_id": "WELTGEWEBE-OS-V1-T067",
            "base_head": "0" * 40,
            "head": "a" * 40,
            "branch": branch,
            "worktree": target_path,
            "effects": ["write"],
            "paths": [str(self.repo / "src" / "example.py")],
            "components": [],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
        unrelated = [
            self._linked(state="unclassified_clean")
            for _ in range(admission.MAX_WORKTREES)
        ]
        for index, row in enumerate(unrelated):
            row["path"] = str(
                self.repo.parent / "worktrees" / f"unrelated-{index}"
            )
            row["branch"] = f"feat/unrelated-{index}"

        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            requested_scope=scope,
            inventory_loader=lambda _repo: {
                "worktrees": [self._main(dirty=True), *unrelated],
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: self._reconciliation(),
        )

        self.assertGreater(
            1 + len(unrelated),
            admission.MAX_WORKTREES,
        )
        self.assertEqual(result["decision"], "allow")
        self.assertNotIn("bounded-inventory-exceeded", result["blocker_codes"])

    def test_repository_scope_above_inventory_bound_remains_fail_closed(self) -> None:
        unrelated = [
            self._linked(state="unclassified_clean")
            for _ in range(admission.MAX_WORKTREES)
        ]
        for index, row in enumerate(unrelated):
            row["path"] = str(
                self.repo.parent / "worktrees" / f"unrelated-{index}"
            )
            row["branch"] = f"feat/unrelated-{index}"

        result = self._assess([self._main(), *unrelated])

        self.assertEqual(result["decision"], "blocked")
        self.assertIn("bounded-inventory-exceeded", result["blocker_codes"])

    def test_different_branch_or_source_alone_never_proves_disjoint_reconciliation(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "fresh-target")
        branch = "fix/fresh-target"
        rows = (
            {
                "blocking": True,
                "checkout_key": "branch-only",
                "state": "orphaned_binding",
                "reasons": ["binding-has-no-current-git-worktree-record"],
                "binding_identity": {"expected_branch": "fix/other"},
            },
            {
                "blocking": True,
                "checkout_key": "source-only",
                "state": "orphaned_binding",
                "reasons": ["binding-has-no-current-git-worktree-record"],
                "binding_identity": {},
                "evidence": {
                    "source": {"kind": "bureau-task", "id": "OTHER-TASK"}
                },
            },
        )
        for row in rows:
            reconciliation = {
                "bindings": [row],
                "pagination": {"has_more": False},
                "source_snapshot": {"repository_errors": []},
                "snapshot_sha256": "b" * 64,
            }
            result = self._assess(
                [self._main()],
                reconciliation=reconciliation,
                requested_scope={"paths": [target_path], "branch": branch},
                target_path=target_path,
                branch=branch,
                source_kind="bureau_task",
                source_id="NEW-TASK",
            )
            self.assertEqual(result["decision"], "converge_first")
            self.assertIn(
                "binding-reconciliation-blocking", result["blocker_codes"]
            )

    def test_relative_inventory_path_never_proves_disjoint_scope(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "fresh-target")
        row = self._linked(state="retained", owner="foreign-owner")
        row["path"] = "relative/worktree"
        result = self._assess(
            [self._main(), row],
            requested_scope={
                "paths": [target_path],
                "branch": "fix/fresh-target",
            },
            target_path=target_path,
            branch="fix/fresh-target",
        )
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("inventory-unobservable", result["blocker_codes"])

    def test_unsafe_agent_paths_remain_repository_wide(self) -> None:
        target_path = str(self.repo.parent / "worktrees" / "agent-target")
        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="agent_workspace_create",
            requested_scope={
                "allowed_paths": ["."],
                "forbidden_paths": [],
                "branch": "fix/agent-target",
            },
            target_path=target_path,
            branch="fix/agent-target",
            inventory_loader=lambda _repo: {
                "worktrees": [self._main(dirty=True)],
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: self._reconciliation(),
        )
        self.assertEqual(result["scope_mode"], "repository")
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("dirty-worktree", result["blocker_codes"])

    def test_clean_detached_source_caches_do_not_block_broad_lane(self) -> None:
        repoground_path = self.repo.parent / ".repoground-sources" / "org__repo__main"
        repobrief_path = self.repo.parent / ".repobrief-sources" / "org__repo__main"
        repoground = {
            "path": str(repoground_path),
            "is_main": False,
            "detached": True,
            "branch": None,
            "status": {"dirty": False},
            "coordination": {
                "blocking": False,
                "resource_leases": [],
                "tasks": [],
                "processes": [],
            },
            "lifecycle": {
                "retention": {
                    "owner_id": "system:repoground-source-cache:org-repo-main",
                },
                "binding": None,
                "latest_archive": None,
            },
            "lifecycle_state": "retained",
        }
        repobrief = {
            "path": str(repobrief_path),
            "is_main": False,
            "detached": True,
            "branch": None,
            "status": {"dirty": False},
            "coordination": {
                "blocking": False,
                "resource_leases": [],
                "tasks": [],
                "processes": [],
            },
            "lifecycle": {
                "retention": {"owner_id": "operator:archive-owner"},
                "binding": None,
                "latest_archive": {
                    "archive_id": "20260802T211037Z-e847e4e5d124",
                    "owner_id": "operator:archive-owner",
                    "cleaned_at_unix": None,
                },
            },
            "lifecycle_state": "archived_retained",
        }
        unclassified = {
            "path": str(
                self.repo.parent / ".repoground-sources" / "org__other__main"
            ),
            "is_main": False,
            "detached": True,
            "branch": None,
            "status": {"dirty": False},
            "coordination": {
                "blocking": False,
                "resource_leases": [],
                "tasks": [],
                "processes": [],
            },
            "lifecycle": {
                "retention": None,
                "binding": None,
                "latest_archive": None,
            },
            "lifecycle_state": "unclassified_clean",
        }
        result = self._assess(
            [self._main(), repoground, repobrief, unclassified]
        )
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["blockers"], [])

    def test_clean_archived_writer_checkout_does_not_block_broad_lane(self) -> None:
        linked = {
            "path": str(self.repo.parent / "worktrees" / "merged-pr"),
            "is_main": False,
            "detached": False,
            "branch": "feat/merged-pr",
            "status": {"dirty": False},
            "coordination": {
                "blocking": False,
                "resource_leases": [],
                "tasks": [],
                "processes": [],
            },
            "lifecycle": {
                "retention": {"owner_id": "archive-owner"},
                "binding": None,
                "latest_archive": {
                    "archive_id": "20260802T234748Z-1f159521375b",
                    "owner_id": "archive-owner",
                    "cleaned_at_unix": None,
                },
            },
            "lifecycle_state": "archived_retained",
        }
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["blockers"], [])

    def test_archived_checkout_with_live_coordination_still_blocks(self) -> None:
        linked = {
            "path": str(self.repo.parent / "worktrees" / "active-pr"),
            "is_main": False,
            "detached": False,
            "branch": "feat/active-pr",
            "status": {"dirty": False},
            "coordination": {
                "blocking": True,
                "resource_leases": [
                    {
                        "blocking": True,
                        "resource_key": "path:/foreign",
                        "owner_id": "foreign-owner",
                    }
                ],
                "tasks": [],
                "processes": [],
            },
            "lifecycle": {
                "retention": {"owner_id": "archive-owner"},
                "binding": None,
                "latest_archive": {
                    "archive_id": "20260802T234748Z-1f159521375b",
                    "owner_id": "archive-owner",
                    "cleaned_at_unix": None,
                },
            },
            "lifecycle_state": "archived_retained",
        }
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("foreign-live-coordination", result["blocker_codes"])
        self.assertIn("worktree-convergence-required", result["blocker_codes"])

    def test_ambiguous_archived_source_cache_remains_blocked(self) -> None:
        linked = {
            "path": str(
                self.repo.parent / ".repobrief-sources" / "org__repo__main"
            ),
            "is_main": False,
            "detached": True,
            "branch": None,
            "status": {"dirty": False},
            "coordination": {
                "blocking": False,
                "resource_leases": [],
                "tasks": [],
                "processes": [],
            },
            "lifecycle": {
                "retention": {"owner_id": "retention-owner"},
                "binding": None,
                "latest_archive": {
                    "archive_id": "20260802T211037Z-e847e4e5d124",
                    "owner_id": "archive-owner",
                    "cleaned_at_unix": None,
                },
            },
            "lifecycle_state": "archived_retained",
        }
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("lifecycle-owner-ambiguous", result["blocker_codes"])
        self.assertIn("worktree-convergence-required", result["blocker_codes"])

    def test_foreign_retained_writer_checkout_still_blocks(self) -> None:
        linked = self._linked(state="retained", owner="foreign-owner")
        linked["detached"] = False
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("foreign-retained-worktree", result["blocker_codes"])

    def test_completed_retained_blocked_requires_convergence_for_same_owner(self) -> None:
        linked = self._linked(
            state="completed_retained_blocked",
            owner="owner-a",
        )
        linked["coordination"]["resource_leases"] = [
            {
                "blocking": True,
                "resource_key": "path:/tmp/same-owner",
                "owner_id": "owner-a",
            }
        ]
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "converge_first")
        self.assertIn("worktree-convergence-required", result["blocker_codes"])
        self.assertNotIn("foreign-live-coordination", result["blocker_codes"])

    def test_exact_expired_owner_target_checkout_does_not_self_block(self) -> None:
        linked = self._linked(state="unclassified_clean")
        linked["head"] = "a" * 40
        target_path = str(linked["path"])
        branch = str(linked["branch"])
        scope = {
            "repository": str(self.repo),
            "worktree": target_path,
            "branch": branch,
            "head": "a" * 40,
        }

        result = self._assess(
            [self._main(), linked],
            requested_scope=scope,
            target_path=target_path,
            branch=branch,
            source_kind="expired_same_owner_lease",
            source_id="f" * 64,
        )

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["blockers"], [])

    def test_expired_owner_target_binding_mismatch_still_requires_convergence(self) -> None:
        linked = self._linked(state="unclassified_clean")
        linked["head"] = "a" * 40
        target_path = str(linked["path"])
        branch = str(linked["branch"])
        scope = {
            "repository": str(self.repo),
            "worktree": target_path,
            "branch": branch,
            "head": "b" * 40,
        }

        result = self._assess(
            [self._main(), linked],
            requested_scope=scope,
            target_path=target_path,
            branch=branch,
            source_kind="expired_same_owner_lease",
            source_id="f" * 64,
        )

        self.assertEqual(result["decision"], "converge_first")
        self.assertIn("worktree-convergence-required", result["blocker_codes"])

    def test_clean_terminal_or_orphaned_state_requires_convergence_first(self) -> None:
        terminal = self._assess(
            [self._main(), self._linked(state="cleanup_candidate")]
        )
        orphaned = self._assess(
            [self._main()], reconciliation=self._reconciliation(blocking=True)
        )
        self.assertEqual(terminal["decision"], "converge_first")
        self.assertIn("worktree-convergence-required", terminal["blocker_codes"])
        self.assertEqual(orphaned["decision"], "converge_first")
        self.assertIn("binding-reconciliation-blocking", orphaned["blocker_codes"])

    def test_convergence_mode_allows_only_clean_convergence_work(self) -> None:
        inventory = lambda _repo: {
            "worktrees": [self._main(), self._linked(state="cleanup_candidate")],
            "inventory_sha256": "a" * 64,
        }
        reconciliation = lambda _repo: self._reconciliation()
        with self.assertRaises(admission.WorkAdmissionBlocked):
            admission.require_repository_admission(
                mode="normal",
                repo=str(self.repo),
                owner_id="owner-a",
                operation="broad_repository_lease",
                inventory_loader=inventory,
                reconciliation_loader=reconciliation,
            )
        result = admission.require_repository_admission(
            mode="convergence",
            repo=str(self.repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            inventory_loader=inventory,
            reconciliation_loader=reconciliation,
        )
        self.assertEqual(result["decision"], "converge_first")

    def test_convergence_mode_never_treats_ambiguous_ownership_as_ownerless(self) -> None:
        linked = self._linked(
            state="managed_lifecycle_drift",
            owner="owner-a",
        )
        linked["lifecycle"]["retention"] = {
            "owner_id": "foreign-owner",
        }
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("lifecycle-owner-ambiguous", result["blocker_codes"])
        blocker = next(
            item
            for item in result["blockers"]
            if item["code"] == "lifecycle-owner-ambiguous"
        )
        self.assertEqual(
            blocker["owner_ids"], ["foreign-owner", "owner-a"]
        )

        with self.assertRaises(admission.WorkAdmissionBlocked):
            admission.require_repository_admission(
                mode="convergence",
                repo=str(self.repo),
                owner_id="owner-a",
                operation="broad_repository_lease",
                inventory_loader=lambda _repo: {
                    "worktrees": [self._main(), linked],
                    "inventory_sha256": "a" * 64,
                },
                reconciliation_loader=lambda _repo: self._reconciliation(),
            )

    def test_convergence_mode_never_overrides_foreign_lifecycle_owner(self) -> None:
        worktrees = [
            self._main(),
            self._linked(
                state="completed_retained",
                owner="foreign-owner",
            ),
        ]
        result = self._assess(worktrees)
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("foreign-lifecycle-owner", result["blocker_codes"])
        self.assertIn("worktree-convergence-required", result["blocker_codes"])

        inventory = lambda _repo: {
            "worktrees": worktrees,
            "inventory_sha256": "a" * 64,
        }
        reconciliation = lambda _repo: self._reconciliation()
        with self.assertRaises(admission.WorkAdmissionBlocked) as raised:
            admission.require_repository_admission(
                mode="convergence",
                repo=str(self.repo),
                owner_id="owner-a",
                operation="broad_repository_lease",
                inventory_loader=inventory,
                reconciliation_loader=reconciliation,
            )
        self.assertEqual(raised.exception.assessment["decision"], "blocked")
        self.assertIn(
            "foreign-lifecycle-owner",
            raised.exception.assessment["blocker_codes"],
        )

    def test_equivalent_source_binding_blocks_duplicate_lane(self) -> None:
        result = self._assess(
            [
                self._main(),
                self._linked(
                    state="retained",
                    owner="owner-a",
                    source_id="GRABOWSKI-T083",
                ),
            ],
            source_kind="bureau_task",
            source_id="GRABOWSKI-T083",
            target_path=str(self.repo.parent / "new-target"),
        )
        self.assertEqual(result["decision"], "converge_first")
        self.assertIn("similar-active-source-binding", result["blocker_codes"])

    def test_same_owner_task_unit_with_distinct_worker_pid_does_not_self_block(self) -> None:
        unit = "grabowski-task-" + "a" * 24 + "-a2.service"
        worker_pid = admission.os.getpid() + 100_000
        linked = self._linked(state="retained", owner="owner-a")
        linked["coordination"] = {
            "resource_leases": [],
            "tasks": [
                {
                    "task_id": "task-a",
                    "lease_owner_id": "owner-a",
                    "unit": unit,
                }
            ],
            "processes": [{"pid": worker_pid, "systemd_units": [unit]}],
        }
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "allow")
        self.assertNotIn("foreign-live-coordination", result["blocker_codes"])

    def test_unattributed_other_process_still_blocks(self) -> None:
        linked = self._linked(state="retained", owner="owner-a")
        linked["coordination"] = {
            "resource_leases": [],
            "tasks": [],
            "processes": [{"pid": admission.os.getpid() + 100_000}],
        }
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("foreign-live-coordination", result["blocker_codes"])

    def test_loader_failure_becomes_typed_unobservable_block(self) -> None:
        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            inventory_loader=lambda _repo: (_ for _ in ()).throw(
                RuntimeError("inventory unavailable")
            ),
            reconciliation_loader=lambda _repo: self._reconciliation(),
        )
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("inventory-unobservable", result["blocker_codes"])
        self.assertTrue(
            any(
                "inventory unavailable" in str(item.get("detail", ""))
                for item in result["blockers"]
            )
        )

    def test_inventory_sqlite_failure_becomes_typed_unobservable_block(
        self,
    ) -> None:
        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            inventory_loader=lambda _repo: (_ for _ in ()).throw(
                sqlite3.OperationalError("task schema drift")
            ),
            reconciliation_loader=lambda _repo: self._reconciliation(),
        )
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("inventory-unobservable", result["blocker_codes"])
        self.assertTrue(
            any(
                "OperationalError: task schema drift"
                in str(item.get("detail", ""))
                for item in result["blockers"]
            )
        )

    def test_reconciliation_sqlite_failure_becomes_typed_unobservable_block(
        self,
    ) -> None:
        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            inventory_loader=lambda _repo: {
                "worktrees": [self._main()],
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: (_ for _ in ()).throw(
                sqlite3.OperationalError("binding schema drift")
            ),
        )
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("reconciliation-unobservable", result["blocker_codes"])
        self.assertTrue(
            any(
                "OperationalError: binding schema drift"
                in str(item.get("detail", ""))
                for item in result["blockers"]
            )
        )

    def test_truncated_reconciliation_is_unobservable_and_blocks(self) -> None:
        result = self._assess(
            [self._main()], reconciliation=self._reconciliation(truncated=True)
        )
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("reconciliation-unobservable", result["blocker_codes"])


    def _reposkop_result(self, repository: str, purpose: str) -> dict[str, object]:
        return {
            "schema_version": 2,
            "kind": "grabowski_reposkop_context",
            "target": {"path": repository, "purpose": purpose},
            "reposkop": {"path": "/tmp/reposkop", "sha256": "f" * 64},
            "report": {
                "kind": "reposkop_coherence_report",
                "schema_version": 2,
                "effect_authorized": False,
                "report_sha256": "a" * 64,
                "observation": {
                    "observation_complete": True,
                    "observation_sha256": "b" * 64,
                    "identities": {
                        "path": repository,
                        "purpose": purpose,
                        "repository_identity_sha256": "c" * 64,
                        "checkout_identity_sha256": "d" * 64,
                    },
                },
                "projection": {
                    "effect_authorized": False,
                    "projection_sha256": "e" * 64,
                },
            },
            "usage_receipt": {
                "path": "/tmp/reposkop-context.json",
                "sha256": "1" * 64,
                "usage_key_sha256": "2" * 64,
                "audit_ref": "audit-record-sha256:" + "3" * 64,
            },
            "effect_authorized": False,
        }

    def test_required_reposkop_context_is_bound_to_admission(self) -> None:
        calls: list[tuple[str, str]] = []

        def load(repository: str, purpose: str) -> dict[str, object]:
            calls.append((repository, purpose))
            return self._reposkop_result(repository, purpose)

        result = admission.require_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="worktree_create",
            inventory_loader=lambda _repo: {
                "worktrees": [self._main()],
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: self._reconciliation(),
            reposkop_required=True,
            reposkop_context_loader=load,
        )
        self.assertEqual(calls, [(str(self.repo.resolve()), admission._reposkop_purpose("worktree_create"))])
        self.assertEqual(result["decision"], "allow")
        self.assertFalse(result["read_only"])
        self.assertTrue(result["evidence_mutation_only"])
        self.assertEqual(result["reposkop_context"]["status"], "verified")
        self.assertEqual(result["reposkop_context"]["repository_identity_sha256"], "c" * 64)
        self.assertEqual(len(result["assessment_sha256"]), 64)

    def test_optional_admission_does_not_invoke_reposkop(self) -> None:
        result = admission.require_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="read_only_question",
            inventory_loader=lambda _repo: {
                "worktrees": [self._main()],
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: self._reconciliation(),
            reposkop_context_loader=lambda _repo, _purpose: self.fail("optional admission invoked Reposkop"),
        )
        self.assertTrue(result["read_only"])
        self.assertNotIn("reposkop_context", result)

    def test_reposkop_failure_blocks_with_typed_reason(self) -> None:
        def unavailable(_repository: str, _purpose: str) -> dict[str, object]:
            raise RuntimeError("Reposkop unavailable")

        with self.assertRaises(admission.WorkAdmissionBlocked) as raised:
            admission.require_repository_admission(
                repo=str(self.repo),
                owner_id="owner-a",
                operation="worktree_create",
                inventory_loader=lambda _repo: {
                    "worktrees": [self._main()],
                    "inventory_sha256": "a" * 64,
                },
                reconciliation_loader=lambda _repo: self._reconciliation(),
                reposkop_required=True,
                reposkop_context_loader=unavailable,
            )
        blocked = raised.exception.assessment
        self.assertEqual(blocked["decision"], "blocked")
        self.assertIn("reposkop-context-unavailable", blocked["blocker_codes"])
        self.assertEqual(blocked["reposkop_context"]["status"], "blocked")

    def test_reposkop_target_mismatch_blocks_fail_closed(self) -> None:
        def mismatched(repository: str, purpose: str) -> dict[str, object]:
            result = self._reposkop_result(repository, purpose)
            result["target"] = {"path": str(self.repo.parent), "purpose": purpose}
            return result

        with self.assertRaises(admission.WorkAdmissionBlocked) as raised:
            admission.require_repository_admission(
                repo=str(self.repo),
                owner_id="owner-a",
                operation="worktree_create",
                inventory_loader=lambda _repo: {
                    "worktrees": [self._main()],
                    "inventory_sha256": "a" * 64,
                },
                reconciliation_loader=lambda _repo: self._reconciliation(),
                reposkop_required=True,
                reposkop_context_loader=mismatched,
            )
        self.assertIn("reposkop-context-unavailable", raised.exception.assessment["blocker_codes"])

    def test_nested_admission_block_is_preserved_as_bounded_cause(self) -> None:
        upstream = {
            "schema_version": 1,
            "kind": "grabowski.repository_work_admission",
            "repository": str(self.repo.resolve()),
            "operation": "reposkop_usage_receipt",
            "decision": "blocked",
            "blocker_codes": ["usage-receipt-write-blocked"],
            "blockers": [
                {
                    "code": "usage-receipt-write-blocked",
                    "detail": "receipt directory is read-only",
                }
            ],
            "assessment_sha256": "9" * 64,
        }

        def blocked(_repository: str, _purpose: str) -> dict[str, object]:
            raise admission.WorkAdmissionBlocked(upstream)

        with self.assertRaises(admission.WorkAdmissionBlocked) as raised:
            admission.require_repository_admission(
                repo=str(self.repo),
                owner_id="owner-a",
                operation="worktree_create",
                inventory_loader=lambda _repo: {
                    "worktrees": [self._main()],
                    "inventory_sha256": "a" * 64,
                },
                reconciliation_loader=lambda _repo: self._reconciliation(),
                reposkop_required=True,
                reposkop_context_loader=blocked,
            )
        result = raised.exception.assessment
        nested = result["reposkop_context"]["upstream_admission"]
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("reposkop-context-unavailable", result["blocker_codes"])
        self.assertEqual(nested["blocker_codes"], ["usage-receipt-write-blocked"])
        self.assertEqual(nested["assessment_sha256"], "9" * 64)
        self.assertEqual(
            nested["blockers"],
            [
                {
                    "code": "usage-receipt-write-blocked",
                    "detail": "receipt directory is read-only",
                }
            ],
        )
        self.assertIsInstance(raised.exception.__cause__, admission.WorkAdmissionBlocked)
        self.assertIs(raised.exception.__cause__.assessment, upstream)

    def test_reposkop_purpose_is_deterministic_and_operation_bound(self) -> None:
        first = admission._reposkop_purpose("worktree_create")
        self.assertEqual(first, admission._reposkop_purpose("worktree_create"))
        self.assertNotEqual(first, admission._reposkop_purpose("runtime_deploy"))
        self.assertIn(":worktree_create:", first)
        sanitized = admission._reposkop_purpose(" Deploy Runtime / Emergency ")
        self.assertIn(":deploy-runtime-emergency:", sanitized)
        self.assertLessEqual(len(first), 128)
        self.assertRegex(first, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
        self.assertRegex(sanitized, r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

    def test_production_worktree_admission_requires_reposkop(self) -> None:
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "grabowski_grips.py"
        ).read_text(encoding="utf-8")
        self.assertIn("reposkop_required=True", source)


if __name__ == "__main__":
    unittest.main()
