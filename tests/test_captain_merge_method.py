from __future__ import annotations

import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class _FakeFastMCP:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def tool(self, *args: object, **kwargs: object):
        del args, kwargs
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs: object) -> None:
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_grips as grips  # noqa: E402


class _RepoPolicyGh:
    def __init__(
        self,
        settings: dict[str, bool],
        branch_rules: list[dict[str, object]] | None = None,
    ) -> None:
        self.settings = settings
        self.branch_rules = list(branch_rules or [])
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, _repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        is_branch_rules = any("/rules/branches/" in argument for argument in argv)
        payload: object = [self.branch_rules] if is_branch_rules else self.settings
        return {
            "returncode": 0,
            "stdout": json.dumps(payload),
            "stderr": "",
        }


class _MergeGh:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, _repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        return {"returncode": 0, "stdout": "", "stderr": ""}


def _settings(
    *, merge: bool = True, squash: bool = True, rebase: bool = True
) -> dict[str, bool]:
    return {
        "allow_merge_commit": merge,
        "allow_squash_merge": squash,
        "allow_rebase_merge": rebase,
        "delete_branch_on_merge": False,
    }


def _pull_request_rule(*methods: str) -> dict[str, object]:
    return {
        "type": "pull_request",
        "parameters": {"allowed_merge_methods": list(methods)},
    }


def _merge_queue_rule(method: str) -> dict[str, object]:
    return {
        "type": "merge_queue",
        "parameters": {"merge_method": method},
    }




class _BranchRulesGh:
    def __init__(self, payloads: list[object]) -> None:
        self.payloads = list(payloads)
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, _repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        payload = self.payloads.pop(0)
        return {
            "returncode": 0,
            "stdout": json.dumps(payload),
            "stderr": "",
        }


def _branch_rules_args() -> list[str]:
    return [
        "api",
        "--method",
        "GET",
        "--paginate",
        "--slurp",
        "-f",
        "per_page=100",
        "repos/heimgewebe/grabowski/rules/branches/main",
    ]


def _branch_guard_runner(gh: _BranchRulesGh, *, explicit: bool = True):
    runner = object.__new__(grips.grabowski_merge_guard.CaptainMergeGuardRunner)
    target: dict[str, object] = {
        "repo": "heimgewebe/grabowski",
        "pr": 96,
        "base": "main",
    }
    if explicit:
        target["merge_method"] = "squash"
    runner.action = {"target": target}
    runner.github_runner = gh
    runner.repo_path = Path.cwd()
    runner.receipt = {}
    runner.branch_merge_policy_args = None
    runner.branch_merge_policy_snapshot = None
    return runner


class CaptainMergeMethodTests(unittest.TestCase):
    def test_explicit_squash_overrides_repository_preference(self) -> None:
        policy, _query, errors = grips._captain_repository_merge_policy(
            Path.cwd(),
            _RepoPolicyGh(_settings()),
            repo_slug="heimgewebe/grabowski",
            requested_method="squash",
            base_branch="main",
        )

        self.assertEqual(errors, [])
        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(policy["allowed_methods"], ["merge", "squash", "rebase"])
        self.assertEqual(policy["requested_method"], "squash")
        self.assertEqual(policy["selected_method"], "squash")
        self.assertEqual(policy["selected_flag"], "--squash")
        self.assertEqual(policy["selection_source"], "explicit_target")

    def test_explicit_method_blocks_when_repository_disables_it(self) -> None:
        policy, _query, errors = grips._captain_repository_merge_policy(
            Path.cwd(),
            _RepoPolicyGh(_settings(squash=False)),
            repo_slug="heimgewebe/grabowski",
            requested_method="squash",
            base_branch="main",
        )

        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(policy["requested_method"], "squash")
        self.assertEqual(policy["selected_method"], "squash")
        self.assertEqual(errors, ["repository_merge_method_not_allowed:squash"])

    def test_explicit_method_respects_branch_allowed_merge_methods(self) -> None:
        policy, _query, errors = grips._captain_repository_merge_policy(
            Path.cwd(),
            _RepoPolicyGh(
                _settings(),
                branch_rules=[_pull_request_rule("squash", "rebase")],
            ),
            repo_slug="heimgewebe/grabowski",
            requested_method="merge",
            base_branch="main",
        )

        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(
            policy["branch_merge_policy"]["pull_request_allowed_methods"],
            ["squash", "rebase"],
        )
        self.assertEqual(errors, ["repository_branch_merge_method_not_allowed:merge"])

    def test_explicit_method_rejects_mismatched_merge_queue_method(self) -> None:
        policy, _query, errors = grips._captain_repository_merge_policy(
            Path.cwd(),
            _RepoPolicyGh(
                _settings(),
                branch_rules=[_merge_queue_rule("SQUASH")],
            ),
            repo_slug="heimgewebe/grabowski",
            requested_method="rebase",
            base_branch="main",
        )

        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(policy["branch_merge_policy"]["merge_queue_method"], "squash")
        self.assertEqual(
            errors,
            ["repository_merge_queue_method_mismatch:rebase:squash"],
        )

    def test_explicit_method_accepts_matching_merge_queue_method(self) -> None:
        policy, _query, errors = grips._captain_repository_merge_policy(
            Path.cwd(),
            _RepoPolicyGh(
                _settings(),
                branch_rules=[
                    _pull_request_rule("squash", "rebase"),
                    _merge_queue_rule("SQUASH"),
                ],
            ),
            repo_slug="heimgewebe/grabowski",
            requested_method="squash",
            base_branch="main",
        )

        self.assertEqual(errors, [])
        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(policy["selected_method"], "squash")
        self.assertIs(policy["branch_merge_policy"]["merge_queue_present"], True)
        self.assertEqual(policy["branch_merge_policy"]["merge_queue_method"], "squash")

    def test_merge_guard_revalidates_explicit_branch_policy_snapshot(self) -> None:
        initial_rules = [
            _pull_request_rule("squash", "rebase"),
            _merge_queue_rule("SQUASH"),
        ]
        reordered_rules = list(reversed(initial_rules))
        gh = _BranchRulesGh([[initial_rules], [reordered_rules]])
        runner = _branch_guard_runner(gh)

        runner(Path.cwd(), _branch_rules_args())
        errors = runner._revalidate_branch_merge_policy()

        self.assertEqual(errors, [])
        self.assertIsNotNone(runner.branch_merge_policy_snapshot)
        self.assertIs(runner.receipt["branch_merge_policy_revalidation"]["matched"], True)
        self.assertEqual(len(gh.calls), 2)

    def test_merge_guard_ignores_unrelated_branch_rule_drift(self) -> None:
        pull_rule = _pull_request_rule("squash", "rebase")
        initial_unrelated = {
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [{"context": "validate"}]},
        }
        drifted_unrelated = {
            "type": "required_status_checks",
            "parameters": {"required_status_checks": [{"context": "validate-2"}]},
        }
        gh = _BranchRulesGh([
            [[pull_rule, initial_unrelated]],
            [[pull_rule, drifted_unrelated]],
        ])
        runner = _branch_guard_runner(gh)

        runner(Path.cwd(), _branch_rules_args())
        errors = runner._revalidate_branch_merge_policy()

        self.assertEqual(errors, [])
        self.assertIs(runner.receipt["branch_merge_policy_revalidation"]["matched"], True)

    def test_merge_guard_blocks_explicit_branch_policy_drift(self) -> None:
        initial_rules = [
            _pull_request_rule("squash", "rebase"),
            _merge_queue_rule("SQUASH"),
        ]
        drifted_rules = [
            _pull_request_rule("squash", "rebase"),
            _merge_queue_rule("REBASE"),
        ]
        gh = _BranchRulesGh([[initial_rules], [drifted_rules]])
        runner = _branch_guard_runner(gh)

        runner(Path.cwd(), _branch_rules_args())
        errors = runner._revalidate_branch_merge_policy()

        self.assertEqual(errors, ["merge_guard_branch_merge_policy_drift"])
        self.assertIs(runner.receipt["branch_merge_policy_revalidation"]["matched"], False)

    def test_merge_guard_legacy_path_does_not_capture_branch_policy(self) -> None:
        rules = [_pull_request_rule("squash", "rebase")]
        gh = _BranchRulesGh([[rules]])
        runner = _branch_guard_runner(gh, explicit=False)

        runner(Path.cwd(), _branch_rules_args())

        self.assertIsNone(runner.branch_merge_policy_args)
        self.assertIsNone(runner.branch_merge_policy_snapshot)
        self.assertEqual(runner._revalidate_branch_merge_policy(), [])
        self.assertNotIn("branch_merge_policy_revalidation", runner.receipt)

    def test_pr_merge_target_rejects_noncanonical_or_unknown_method(self) -> None:
        for merge_method in ("SQUASH", "octopus", " squash"):
            with self.subTest(merge_method=merge_method):
                with self.assertRaisesRegex(
                    grips.GripPreflightError,
                    "target.merge_method must be one of",
                ):
                    grips._validate_captain_target(
                        "pr-merge",
                        {
                            "repo": "heimgewebe/grabowski",
                            "pr": 96,
                            "base": "main",
                            "merge_method": merge_method,
                        },
                        index=0,
                    )

    def test_merge_method_is_bound_into_target_hash_and_evidence_schema(self) -> None:
        target = {
            "repo": "heimgewebe/grabowski",
            "pr": 96,
            "base": "main",
            "merge_method": "squash",
        }
        legacy_target = {
            "repo": "heimgewebe/grabowski",
            "pr": 96,
            "base": "main",
        }

        grips._validate_captain_target("pr-merge", target, index=0)
        schema = grips._captain_action_evidence_schema(
            "pr-merge",
            target,
            {"irreversibility": "reversible", "recovery_path": "revert merge"},
        )

        self.assertEqual(schema["target_binding"]["merge_method"], "squash")
        self.assertNotEqual(
            grips._captain_target_sha256(target),
            grips._captain_target_sha256(legacy_target),
        )

    def test_pr_merge_executor_forwards_bound_method_and_dispatches_exact_flag(
        self,
    ) -> None:
        expected_head = "a" * 40
        expected_base_sha = "b" * 40
        target = {
            "repo": "heimgewebe/grabowski",
            "pr": 96,
            "base": "main",
            "merge_method": "squash",
        }
        action = {"target": target}
        parameters = {
            "expected_head": expected_head,
            "expected_base_sha": expected_base_sha,
        }
        requested: dict[str, object] = {}

        def policy(
            _repo_path,
            _github_runner,
            *,
            repo_slug,
            requested_method=None,
            base_branch=None,
        ):
            requested["repo_slug"] = repo_slug
            requested["method"] = requested_method
            requested["base_branch"] = base_branch
            return (
                {
                    "settings": _settings(),
                    "allowed_methods": ["merge", "squash", "rebase"],
                    "requested_method": requested_method,
                    "selected_method": "squash",
                    "selected_policy_field": "allow_squash_merge",
                    "selected_flag": "--squash",
                    "selection_source": "explicit_target",
                    "preference_order": ["merge", "squash", "rebase"],
                },
                {},
                [],
            )

        gh = _MergeGh()
        with (
            mock.patch.object(
                grips,
                "_captain_pr_merge_preflight_view",
                return_value=({"state": "OPEN"}, {}, []),
            ),
            mock.patch.object(
                grips,
                "_captain_repository_merge_policy",
                side_effect=policy,
            ),
            mock.patch.object(
                grips.grabowski_merge_guard,
                "verify_github_base_update_guard",
                return_value=({"mode": "test"}, {}, []),
            ),
            mock.patch.object(
                grips,
                "_captain_pr_merge_effect_scope_decision",
                return_value={
                    "decision": "passed",
                    "reasons": [],
                    "configured_automatic_effects": [],
                },
            ),
            mock.patch.object(
                grips,
                "_captain_pr_merge_post_view",
                return_value=({"state": "MERGED"}, [], [], {}),
            ),
        ):
            result = grips._run_captain_pr_merge(Path.cwd(), action, parameters, gh)

        self.assertEqual(
            requested,
            {
                "repo_slug": "heimgewebe/grabowski",
                "method": "squash",
                "base_branch": "main",
            },
        )
        merge_call = next(call for call in gh.calls if call[:2] == ("pr", "merge"))
        self.assertIn("--squash", merge_call)
        self.assertNotIn("--merge", merge_call)
        self.assertIn(expected_head, merge_call)
        self.assertEqual(result["requested_merge_method"], "squash")
        self.assertIs(result["verification_passed"], True)


if __name__ == "__main__":
    unittest.main()
