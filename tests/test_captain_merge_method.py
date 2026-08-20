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
    def __init__(self, settings: dict[str, bool]) -> None:
        self.settings = settings
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, _repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        return {
            "returncode": 0,
            "stdout": json.dumps(self.settings),
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


class CaptainMergeMethodTests(unittest.TestCase):
    def test_explicit_squash_overrides_repository_preference(self) -> None:
        policy, _query, errors = grips._captain_repository_merge_policy(
            Path.cwd(),
            _RepoPolicyGh(_settings()),
            repo_slug="heimgewebe/grabowski",
            requested_method="squash",
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
        )

        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(policy["requested_method"], "squash")
        self.assertEqual(policy["selected_method"], "squash")
        self.assertEqual(errors, ["repository_merge_method_not_allowed:squash"])

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

        def policy(_repo_path, _github_runner, *, repo_slug, requested_method=None):
            requested["repo_slug"] = repo_slug
            requested["method"] = requested_method
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
            {"repo_slug": "heimgewebe/grabowski", "method": "squash"},
        )
        merge_call = next(call for call in gh.calls if call[:2] == ("pr", "merge"))
        self.assertIn("--squash", merge_call)
        self.assertNotIn("--merge", merge_call)
        self.assertIn(expected_head, merge_call)
        self.assertEqual(result["requested_merge_method"], "squash")
        self.assertIs(result["verification_passed"], True)


if __name__ == "__main__":
    unittest.main()
